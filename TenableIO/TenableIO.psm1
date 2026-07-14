<#
  TenableIO.psm1 - PowerShell client for Tenable Vulnerability Management (cloud.tenable.com).

  Compatible with Windows PowerShell 5.1 (Desktop) and PowerShell 7+ (Core).

  Credential design mirrors tenable-io-python. Resolution order:
      -AccessKey / -SecretKey parameter
      ->  $env:TIO_ACCESS_KEY / $env:TIO_SECRET_KEY            (value)
      ->  $env:TIO_ACCESS_KEY_CMD / $env:TIO_SECRET_KEY_CMD    (vault command; stdout is the key)
      ->  OS secret store:
             Microsoft.PowerShell.SecretManagement vault, if one is registered; else
             Windows  -> DPAPI-encrypted file (per-user, encrypted at rest)
             Linux/mac-> a 0600 owner-only file (read is refused unless owner-only - fail closed)

  Values are entered at a hidden prompt (Read-Host -AsSecureString) and passed by API/stdin -
  never on the command line. Keys are only ever sent to cloud.tenable.com over TLS.
#>

Set-StrictMode -Version Latest

# Platform detection that works on BOTH Windows PowerShell 5.1 (where $IsWindows does not exist -
# and referencing it under StrictMode would throw) and PowerShell 7 (where it does). OSVersion.Platform
# is available on .NET Framework and .NET Core alike.
$script:OnWindows = ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT)

# Windows PowerShell 5.1 negotiates TLS 1.0/1.1 by default, which cloud.tenable.com rejects. Force
# TLS 1.2 (leave anything already enabled, e.g. 1.3). No-op / harmless on PowerShell 7.
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}

$script:ServiceName  = 'tenable-io'
$script:BaseUrl      = 'https://cloud.tenable.com'
$script:Session      = $null   # @{ AccessKey; SecretKey; BaseUrl } after Connect-TIO
$script:MinFreeBytes = 2GB     # exports abort if free disk on the target drive drops below this

# -- helpers ---------------------------------------------------------------
function ConvertFrom-TIOSecure {
    param([System.Security.SecureString]$Secure)
    if (-not $Secure) { return '' }
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try   { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

function Get-TIODataDir {
    if ($script:OnWindows) { return (Join-Path $env:LOCALAPPDATA 'tio_client') }
    $base = if ($env:XDG_DATA_HOME) { $env:XDG_DATA_HOME } else { Join-Path $HOME '.local/share' }
    return (Join-Path $base 'tio_client')
}
function Get-TIOKeyFile { Join-Path (Get-TIODataDir) 'keys.json' }

# Vault command hook - run $env:<name> and use its stdout as the key. Nothing is written to disk.
function Invoke-TIOKeyCommand {
    param([string]$EnvName)
    $cmd = [Environment]::GetEnvironmentVariable($EnvName)
    if ([string]::IsNullOrWhiteSpace($cmd)) { return '' }
    try {
        if ($script:OnWindows) { $out = & $env:ComSpec /c $cmd 2>$null }
        else                   { $out = & '/bin/sh' -c $cmd 2>$null }
        if ($LASTEXITCODE -eq 0 -and $out) { return (($out -join "`n").Trim()) }
        Write-Warning "$EnvName exited with code $LASTEXITCODE"
    } catch { Write-Warning "$EnvName failed: $_" }
    return ''
}

# -- OS secret store -------------------------------------------------------
function Get-TIOVaultName {
    if (-not (Get-Module -ListAvailable -Name Microsoft.PowerShell.SecretManagement)) { return $null }
    try {
        Import-Module Microsoft.PowerShell.SecretManagement -ErrorAction Stop
        $v = Get-SecretVault -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($v) { return $v.Name }
    } catch { }
    return $null
}

# Fail closed: on Unix, refuse the key file unless it's owner-only (a bad umask or a planted file
# must not leak keys). DPAPI on Windows already binds the file to the user, so no check there.
# Uses stat (GNU or BSD/macOS) rather than the .NET 7 UnixFileMode API, so nothing here needs 5.1
# to have modern .NET (and this branch never runs on Windows anyway).
function Test-TIOFileSafe {
    param([string]$Path)
    if ($script:OnWindows) { return $true }
    $mode = & stat -c '%a' $Path 2>$null            # GNU / Linux
    if (-not $mode) { $mode = & stat -f '%Lp' $Path 2>$null }   # BSD / macOS
    if ($mode) {
        try {
            $m = [Convert]::ToInt32(("$mode").Trim(), 8)
            if ($m -band 0x3F) {                    # 0o077 = any group/other bit set
                Write-Warning "Refusing to read $Path - it is group/other-accessible (mode $mode). Fix: chmod 600 '$Path'"
                return $false
            }
        } catch { }
    }
    return $true
}

function Get-TIOFileStore {
    $p = Get-TIOKeyFile
    if (-not (Test-Path -LiteralPath $p)) { return @{} }
    if (-not (Test-TIOFileSafe $p))       { return @{} }
    try {
        $raw = Get-Content -LiteralPath $p -Raw | ConvertFrom-Json
        $h = @{}; foreach ($k in 'access','secret') { if ($raw.PSObject.Properties.Name -contains $k) { $h[$k] = $raw.$k } }
        return $h
    } catch { return @{} }
}

function Set-TIOFileStore {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '',
        Justification = 'DPAPI-encrypts the already-plaintext API key for at-rest storage on Windows; the value is plaintext at the API boundary regardless.')]
    param([string]$Account, [string]$Value)
    $dir = Get-TIODataDir
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    if (-not $script:OnWindows) { & chmod 700 $dir 2>$null }
    $store = Get-TIOFileStore
    # Windows: encrypt the value at rest with DPAPI (CurrentUser). Unix: store plaintext behind 0600.
    $store[$Account] = if ($script:OnWindows) { ConvertFrom-SecureString (ConvertTo-SecureString $Value -AsPlainText -Force) } else { $Value }
    $p = Get-TIOKeyFile
    ($store | ConvertTo-Json) | Set-Content -LiteralPath $p -Encoding utf8
    if (-not $script:OnWindows) { & chmod 600 $p 2>$null }
    return $true
}

function Get-TIOStoreKey {
    param([ValidateSet('access','secret')][string]$Account)
    # 1. SecretManagement vault, if registered
    $vault = Get-TIOVaultName
    if ($vault) {
        try {
            $s = Get-Secret -Name "$script:ServiceName-$Account" -Vault $vault -AsPlainText -ErrorAction Stop
            if ($s) { return $s }
        } catch { }
    }
    # 2. file store (DPAPI-encrypted on Windows, 0600 plaintext on Unix)
    $store = Get-TIOFileStore
    if ($store.ContainsKey($Account) -and $store[$Account]) {
        $val = $store[$Account]
        if ($script:OnWindows) { try { return (ConvertFrom-TIOSecure (ConvertTo-SecureString $val)) } catch { return '' } }
        return $val
    }
    return ''
}

function Set-TIOStoreKey {
    param([ValidateSet('access','secret')][string]$Account, [string]$Value)
    $vault = Get-TIOVaultName
    if ($vault) {
        try { Set-Secret -Name "$script:ServiceName-$Account" -Secret $Value -Vault $vault -ErrorAction Stop; return $true } catch { }
    }
    return (Set-TIOFileStore -Account $Account -Value $Value)
}

# Resolve one key: env value -> env command -> OS store.
function Resolve-TIOKey {
    param([ValidateSet('access','secret')][string]$Account)
    $envValue = if ($Account -eq 'access') { $env:TIO_ACCESS_KEY } else { $env:TIO_SECRET_KEY }
    if ($envValue) { return $envValue }
    $cmdName  = if ($Account -eq 'access') { 'TIO_ACCESS_KEY_CMD' } else { 'TIO_SECRET_KEY_CMD' }
    $fromCmd  = Invoke-TIOKeyCommand $cmdName
    if ($fromCmd) { return $fromCmd }
    return (Get-TIOStoreKey -Account $Account)
}

# -- public API ------------------------------------------------------------
function Get-TIOKeySource {
    <#
.SYNOPSIS
Report which credential store this host would use (no secrets shown).
#>
    [CmdletBinding()] [OutputType([string])] param()
    $vault = Get-TIOVaultName
    if     ($vault)              { "SecretManagement vault '$vault'" }
    elseif ($script:OnWindows)   { "Windows DPAPI file ($(Get-TIOKeyFile))" }
    else                         { "0600 owner-only file ($(Get-TIOKeyFile))" }
}

function Set-TIOCredential {
    <#
.SYNOPSIS
Prompt for the Tenable API access + secret keys and save them to the OS secret store.
.DESCRIPTION
Hidden prompts (entered twice); validates with a session lookup afterwards.
#>
    [CmdletBinding()] param([switch]$SkipValidate)
    Write-Host "Storing Tenable API keys in $(Get-TIOKeySource) (service '$script:ServiceName')." -ForegroundColor Cyan
    foreach ($pair in @(@('access','ACCESS'), @('secret','SECRET'))) {
        $account, $label = $pair
        $s1 = Read-Host -AsSecureString "-> Enter your Tenable $label key (hidden)"
        $s2 = Read-Host -AsSecureString "   Re-enter to confirm"
        $v1 = ConvertFrom-TIOSecure $s1; $v2 = ConvertFrom-TIOSecure $s2
        if (-not $v1)      { Write-Error "Empty $label key; aborting."; return }
        if ($v1 -ne $v2)   { Write-Error "The two $label entries didn't match; aborting."; return }
        if (-not (Set-TIOStoreKey -Account $account -Value $v1)) { Write-Error "Failed to store the $label key."; return }
    }
    Write-Host "Stored." -ForegroundColor Green
    if ($SkipValidate) { return }
    try {
        $me = Connect-TIO -PassThru | ForEach-Object { Get-TIOSession }
        Write-Host ("OK - authenticated as {0} ({1}), container {2}." -f $me.username, $me.name, $me.container_id) -ForegroundColor Green
    } catch { Write-Warning "Keys were stored, but validation failed: $_" }
}

function Connect-TIO {
    <#
.SYNOPSIS
Resolve the API keys and stash them for subsequent cmdlets.
.PARAMETER AccessKey
Optional explicit access key (overrides env / store).
.PARAMETER SecretKey
Optional explicit secret key.
#>
    [CmdletBinding()] param(
        [string]$AccessKey,
        [string]$SecretKey,
        [string]$BaseUrl = $script:BaseUrl,
        [switch]$PassThru
    )
    if (-not $AccessKey) { $AccessKey = Resolve-TIOKey -Account 'access' }
    if (-not $SecretKey) { $SecretKey = Resolve-TIOKey -Account 'secret' }
    if (-not $AccessKey -or -not $SecretKey) {
        throw ("No API keys found. Provide them one of three ways:`n" +
               "  1. Save them:  Set-TIOCredential   (uses $(Get-TIOKeySource))`n" +
               "  2. Environment: `$env:TIO_ACCESS_KEY / `$env:TIO_SECRET_KEY (or the *_CMD vault hooks)`n" +
               "  3. Connect-TIO -AccessKey ... -SecretKey ...`n" +
               "Create a key pair in Tenable: Settings -> My Account -> API Keys.")
    }
    $script:Session = @{ AccessKey = $AccessKey; SecretKey = $SecretKey; BaseUrl = $BaseUrl.TrimEnd('/') }
    if ($PassThru) { [pscustomobject]$script:Session }
}

# Shared request with retry on 429 / 5xx (matches the Python client's backoff).
function Invoke-TIORequest {
    param([string]$Method, [string]$Path, [hashtable]$Body, [string]$What = 'request', [int]$TimeoutSec = 180)
    if (-not $script:Session) { Connect-TIO | Out-Null }
    $uri = "$($script:Session.BaseUrl)$Path"
    $headers = @{ 'X-ApiKeys' = "accessKey=$($script:Session.AccessKey);secretKey=$($script:Session.SecretKey)"; 'Accept' = 'application/json' }
    $max = 5
    for ($attempt = 1; $attempt -le $max; $attempt++) {
        try {
            $p = @{ Method = $Method; Uri = $uri; Headers = $headers; TimeoutSec = $TimeoutSec }
            if ($PSBoundParameters.ContainsKey('Body') -and $null -ne $Body) {
                $p.Body = ($Body | ConvertTo-Json -Depth 10); $p.ContentType = 'application/json'
            }
            return Invoke-RestMethod @p
        } catch {
            $code = 0
            try { if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode } } catch { }
            if (($code -eq 429 -or ($code -ge 500 -and $code -lt 600)) -and $attempt -lt $max) {
                Start-Sleep -Seconds ([math]::Min(30, [math]::Pow(2, $attempt))); continue
            }
            if ($code -eq 401 -or $code -eq 403) { throw "${What}: HTTP $code - check the key and the key user's role." }
            throw "$What failed$(if ($code) { " (HTTP $code)" }): $($_.Exception.Message)"
        }
    }
}

function Get-TIOSession {
    <#
.SYNOPSIS
Validate the connection - returns your Tenable account (the /session endpoint).
#>
    [CmdletBinding()] param()
    Invoke-TIORequest -Method GET -Path '/session' -What 'session'
}

# -- bulk export engine ----------------------------------------------------
# Generic Tenable export: POST /{kind}/export -> poll status -> download chunks as they appear.
# Emits each record to the pipeline (streaming, so memory stays flat). kind in vulns|assets|compliance.
function Invoke-TIOExport {
    param([ValidateSet('vulns', 'assets', 'compliance')][string]$Kind, [hashtable]$Body,
          [double]$PollSeconds = 2.0, [int]$TimeoutSeconds = 7200)
    $start = Invoke-TIORequest -Method POST -Path "/$Kind/export" -Body $Body -What "$Kind export start"
    $uuid  = Get-TIOProp $start 'export_uuid'
    if (-not $uuid) { $uuid = Get-TIOProp $start 'uuid' }
    if (-not $uuid) { throw "$Kind export did not return an export_uuid." }
    Write-Verbose "$Kind export $uuid started"
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    $waited = 0.0
    while ($true) {
        $st = Invoke-TIORequest -Method GET -Path "/$Kind/export/$uuid/status" -What "$Kind export status"
        foreach ($cid in @(Get-TIOProp $st 'chunks_available')) {
            if (-not $seen.Add([string]$cid)) { continue }
            $chunk = Invoke-TIORequest -Method GET -Path "/$Kind/export/$uuid/chunks/$cid" -What "$Kind export chunk $cid"
            foreach ($rec in @($chunk)) { $rec }
        }
        $status = ("" + (Get-TIOProp $st 'status')).ToUpper()
        if ($status -eq 'FINISHED') { break }
        if ('ERROR', 'CANCELLED' -contains $status) { throw "$Kind export ended with status $status" }
        Start-Sleep -Seconds $PollSeconds
        $waited += $PollSeconds
        if ($waited -gt $TimeoutSeconds) { throw "$Kind export timed out after ${TimeoutSeconds}s (uuid $uuid)" }
    }
}

# Seconds since the Unix epoch (UTC), for the export API's time filters.
function Get-TIOUnixTime { param([datetime]$Dt)
    [int64](New-TimeSpan -Start ([datetime]'1970-01-01Z') -End $Dt.ToUniversalTime()).TotalSeconds
}

# Emit to the pipeline, or stream to a JSONL file with a free-disk safety net.
function Write-TIOExport {
    param([string]$Kind, [hashtable]$Body, [string]$Path, [string]$Label)
    if (-not $Path) { Invoke-TIOExport -Kind $Kind -Body $Body; return }
    $full  = [System.IO.Path]::GetFullPath($Path)
    $drive = [System.IO.DriveInfo]::new([System.IO.Path]::GetPathRoot($full))
    $writer = [System.IO.StreamWriter]::new($full, $false)
    $n = 0
    try {
        Invoke-TIOExport -Kind $Kind -Body $Body | ForEach-Object {
            if (($n % 1000) -eq 0 -and $drive.AvailableFreeSpace -lt $script:MinFreeBytes) {
                throw "Aborting $Label export: free disk on '$($drive.Name)' is below $([math]::Round($script:MinFreeBytes/1GB,1)) GB (wrote $n records to $full)."
            }
            $writer.WriteLine(($_ | ConvertTo-Json -Compress -Depth 50))
            $n++
            if (($n % 5000) -eq 0) { Write-Host "  ${Label}: $n ..." }
        }
    } finally { $writer.Dispose() }
    Write-Host "[ok] $Label -> $n records at $full" -ForegroundColor Green
}

function Export-TIOVuln {
    <#
.SYNOPSIS
Export vulnerability findings via the async export API.
.DESCRIPTION
By default exports only CURRENT findings (OPEN + REOPENED). Pass -All to also include FIXED
(remediated) history - i.e. every finding - which can be very large. Or pass -State to choose exact
states. Additional filters (severity, VPR, plugin, network, tag) are applied server-side so only the
matching slice is transferred. With -Path, streams JSONL to a file (free-disk guarded); else emits objects.
.PARAMETER All
Export ALL findings including FIXED/remediated history. This is the full, potentially huge pull, so
it must be requested explicitly. Cannot be combined with -State.
.PARAMETER State
Exact state(s) to export (OPEN, REOPENED, FIXED). Overrides the default; cannot be combined with -All.
.PARAMETER Severity
Restrict to one or more severities (info, low, medium, high, critical).
.PARAMETER VprMin
Only findings whose VPR score is >= this value (0-10). Note: the export API filters on VPR, not CVSS.
.PARAMETER VprMax
Only findings whose VPR score is <= this value (0-10).
.PARAMETER PluginId
Restrict to specific Nessus plugin ID(s).
.PARAMETER PluginFamily
Restrict to specific plugin family name(s), e.g. 'Windows', 'General'.
.PARAMETER NetworkId
Restrict to a network UUID (the default network is all-zeros).
.PARAMETER Cidr
Restrict to assets within a CIDR range, e.g. '10.0.0.0/8'.
.PARAMETER Tag
Restrict by asset tag(s). A hashtable of category -> value(s):
-Tag @{ BU = 'AMI'; Environment = 'Production','Staging' }
.PARAMETER Source
Restrict to findings from a given collection source: NESSUS (network scan), AGENT, or NNM (passive).
.PARAMETER SeverityModification
Restrict by how severity was set: NONE (unmodified), ACCEPTED (accept-risk), or RECASTED.
.PARAMETER PluginType
Restrict to a plugin type: remote, local, combined, summary, reputation, or third_party.
.PARAMETER Since
Only findings seen since this date/time (the 'since' convenience filter; bounds by last-seen).
.PARAMETER FirstFound
Only findings first detected on/after this date/time (net-new findings in a window).
.PARAMETER LastFound
Only findings last seen on/after this date/time (precise last-seen cutoff).
.PARAMETER LastFixed
Only findings fixed on/after this date/time - remediation verification (pair with -State FIXED / -All).
.PARAMETER IndexedSince
Only findings indexed into Tenable on/after this date/time (data-freshness / pipeline use).
.EXAMPLE
Export-TIOVuln -Severity critical -VprMin 9 -Tag @{ BU = 'AMI' } -Path ./crown-jewels-crit.jsonl
.EXAMPLE
Export-TIOVuln -State FIXED -LastFixed (Get-Date).AddDays(-30)        # what got remediated this month
.EXAMPLE
Export-TIOVuln -Source AGENT -Severity high,critical                  # agent-collected high/crit only
#>
    [CmdletBinding(DefaultParameterSetName = 'Current')] param(
        [Parameter(ParameterSetName = 'All')]
        [switch]$All,
        [Parameter(ParameterSetName = 'ByState')]
        [ValidateSet('OPEN', 'REOPENED', 'FIXED')][string[]]$State,
        [ValidateSet('info', 'low', 'medium', 'high', 'critical')][string[]]$Severity,
        [ValidateRange(0, 10)][double]$VprMin,
        [ValidateRange(0, 10)][double]$VprMax,
        [int[]]$PluginId,
        [string[]]$PluginFamily,
        [ValidateSet('remote', 'local', 'combined', 'summary', 'reputation', 'third_party')]
        [string]$PluginType,
        [ValidateSet('NESSUS', 'AGENT', 'NNM')][string[]]$Source,
        [ValidateSet('NONE', 'ACCEPTED', 'RECASTED')][string[]]$SeverityModification,
        [string]$NetworkId,
        [string]$Cidr,
        [hashtable]$Tag,
        [datetime]$Since,
        [datetime]$FirstFound,
        [datetime]$LastFound,
        [datetime]$LastFixed,
        [datetime]$IndexedSince,
        [int]$NumAssets = 500,
        [string]$Path
    )
    # @(...) forces an array: a bare if-expression unwraps a single-element result to a scalar,
    # which would serialize 'state' as "FIXED" instead of ["FIXED"] and the API rejects it (400).
    $states = @( if ($All) { 'OPEN', 'REOPENED', 'FIXED' }
                 elseif ($State) { $State }
                 else { 'OPEN', 'REOPENED' } )       # default: current findings only, not FIXED history
    Write-Verbose ("Exporting vuln states: {0}" -f ($states -join ', '))
    $filters = @{ state = $states }
    if ($Severity)             { $filters.severity = $Severity }
    if ($PluginId)             { $filters.plugin_id = $PluginId }
    if ($PluginFamily)         { $filters.plugin_family = $PluginFamily }
    if ($PluginType)           { $filters.plugin_type = $PluginType }
    if ($Source)               { $filters.source = $Source }
    if ($SeverityModification) { $filters.severity_modification_type = $SeverityModification }
    if ($NetworkId)            { $filters.network_id = $NetworkId }
    if ($Cidr)                 { $filters.cidr_range = $Cidr }
    if ($Tag)                  { foreach ($k in $Tag.Keys) { $filters["tag.$k"] = @($Tag[$k]) } }
    if ($PSBoundParameters.ContainsKey('Since'))        { $filters.since = Get-TIOUnixTime $Since }
    if ($PSBoundParameters.ContainsKey('FirstFound'))   { $filters.first_found = Get-TIOUnixTime $FirstFound }
    if ($PSBoundParameters.ContainsKey('LastFound'))    { $filters.last_found = Get-TIOUnixTime $LastFound }
    if ($PSBoundParameters.ContainsKey('LastFixed'))    { $filters.last_fixed = Get-TIOUnixTime $LastFixed }
    if ($PSBoundParameters.ContainsKey('IndexedSince')) { $filters.indexed_at = Get-TIOUnixTime $IndexedSince }
    if ($PSBoundParameters.ContainsKey('VprMin') -or $PSBoundParameters.ContainsKey('VprMax')) {
        $vpr = @{}
        if ($PSBoundParameters.ContainsKey('VprMin')) { $vpr.gte = $VprMin }
        if ($PSBoundParameters.ContainsKey('VprMax')) { $vpr.lte = $VprMax }
        $filters.vpr_score = $vpr
    }
    $body = @{ num_assets = $NumAssets; include_unlicensed = $true; filters = $filters }
    Write-TIOExport -Kind vulns -Body $body -Path $Path -Label 'vulns'
}

function Export-TIOAsset {
    <#
.SYNOPSIS
Export assets (hosts) with their attributes, tags, sources, and last-seen data.
#>
    [CmdletBinding()] param([int]$ChunkSize = 1000, [string]$Path)
    Write-TIOExport -Kind assets -Body @{ chunk_size = $ChunkSize } -Path $Path -Label 'assets'
}

function Export-TIOCompliance {
    <#
.SYNOPSIS
Export compliance/audit findings. Use -Since to avoid the (often huge) full history.
#>
    [CmdletBinding()] param([datetime]$Since, [int]$NumFindings = 5000, [string]$Path)
    $body = @{ num_findings = $NumFindings }
    if ($Since) { $body.filters = @{ last_seen = [int64](New-TimeSpan -Start ([datetime]'1970-01-01Z') -End $Since.ToUniversalTime()).TotalSeconds } }
    Write-TIOExport -Kind compliance -Body $body -Path $Path -Label 'compliance'
}

# -- config / inventory reads ----------------------------------------------
function Get-TIOProp { param($Obj, [string]$Name)   # strict-mode-safe property access
    if ($Obj -and ($Obj.PSObject.Properties.Name -contains $Name)) { $Obj.$Name }
}
function Get-TIOPaged {                              # walk offset/limit pagination, emit all items
    param([string]$Path, [string]$ItemKey, [int]$Limit = 1000, [string]$What)
    $offset = 0
    while ($true) {
        $sep  = if ($Path.Contains('?')) { '&' } else { '?' }
        $resp = Invoke-TIORequest -Method GET -Path "$Path${sep}limit=$Limit&offset=$offset" -What $What
        $items = @(Get-TIOProp $resp $ItemKey)
        $items
        if ($items.Count -lt $Limit) { break }
        $offset += $Limit
    }
}

<#
.SYNOPSIS
List scan configurations.
#>
function Get-TIOScan          { [CmdletBinding()] param() Get-TIOProp (Invoke-TIORequest GET '/scans'      -What 'scans')      'scans' }
<#
.SYNOPSIS
List scanners (sensors).
#>
function Get-TIOScanner       { [CmdletBinding()] param() Get-TIOProp (Invoke-TIORequest GET '/scanners'   -What 'scanners')   'scanners' }
<#
.SYNOPSIS
List scan policies.
#>
function Get-TIOPolicy        { [CmdletBinding()] param() Get-TIOProp (Invoke-TIORequest GET '/policies'   -What 'policies')   'policies' }
<#
.SYNOPSIS
List networks.
#>
function Get-TIONetwork       { [CmdletBinding()] param() Get-TIOProp (Invoke-TIORequest GET '/networks'   -What 'networks')   'networks' }
<#
.SYNOPSIS
List scan exclusions.
#>
function Get-TIOExclusion     { [CmdletBinding()] param() Get-TIOProp (Invoke-TIORequest GET '/exclusions' -What 'exclusions') 'exclusions' }
<#
.SYNOPSIS
List users.
#>
function Get-TIOUser          { [CmdletBinding()] param() Get-TIOProp (Invoke-TIORequest GET '/users'      -What 'users')      'users' }
<#
.SYNOPSIS
List user groups.
#>
function Get-TIOGroup         { [CmdletBinding()] param() Get-TIOProp (Invoke-TIORequest GET '/groups'     -What 'groups')     'groups' }
<#
.SYNOPSIS
Get the Tenable.io server status.
#>
function Get-TIOServerStatus  { [CmdletBinding()] param() Invoke-TIORequest GET '/server/status' -What 'server status' }
<#
.SYNOPSIS
List tag values (paged).
#>
function Get-TIOTag           { [CmdletBinding()] param([int]$Limit = 1000) Get-TIOPaged -Path '/tags/values' -ItemKey 'values' -Limit $Limit -What 'tag values' }

function Get-TIOAgent {
    <#
.SYNOPSIS
List linked agents with their last-connect times.
.DESCRIPTION
Agents live under the agent-manager scanner (id 1 by default). Pass -ScannerId to
target one scanner (fast); use -AllScanners to sweep every scanner (thorough, slow on big tenants).
#>
    [CmdletBinding()] param([int]$ScannerId = 1, [switch]$AllScanners, [int]$Limit = 1000)
    $scanners = if ($AllScanners) { @(Get-TIOScanner) } else { @([pscustomobject]@{ id = $ScannerId }) }
    foreach ($sc in $scanners) {
        if (-not (Get-TIOProp $sc 'id')) { continue }
        Get-TIOPaged -Path "/scanners/$($sc.id)/agents" -ItemKey 'agents' -Limit $Limit -What "agents (scanner $($sc.id))"
    }
}
function Get-TIOAgentGroup {
    <#
.SYNOPSIS
List agent groups across all scanners.
#>
    [CmdletBinding()] param()
    foreach ($sc in @(Get-TIOScanner)) {
        if (-not (Get-TIOProp $sc 'id')) { continue }
        Get-TIOProp (Invoke-TIORequest GET "/scanners/$($sc.id)/agent-groups" -What "agent-groups (scanner $($sc.id))") 'groups'
    }
}

Export-ModuleMember -Function Connect-TIO, Set-TIOCredential, Get-TIOSession,
    Get-TIOKeySource, Export-TIOVuln, Export-TIOAsset, Export-TIOCompliance,
    Get-TIOScan, Get-TIOScanner, Get-TIOAgent, Get-TIOAgentGroup, Get-TIOTag,
    Get-TIOPolicy, Get-TIONetwork, Get-TIOExclusion, Get-TIOUser, Get-TIOGroup,
    Get-TIOServerStatus
