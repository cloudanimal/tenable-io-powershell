<#
  TenableIO.psm1 — PowerShell client for Tenable Vulnerability Management (cloud.tenable.com).

  Credential design mirrors tenable-io-python. Resolution order:
      -AccessKey / -SecretKey parameter
      →  $env:TIO_ACCESS_KEY / $env:TIO_SECRET_KEY            (value)
      →  $env:TIO_ACCESS_KEY_CMD / $env:TIO_SECRET_KEY_CMD    (vault command; stdout is the key)
      →  OS secret store:
             Microsoft.PowerShell.SecretManagement vault, if one is registered; else
             Windows  → DPAPI-encrypted file (per-user, encrypted at rest)
             Linux/mac→ a 0600 owner-only file (read is refused unless owner-only — fail closed)

  Values are entered at a hidden prompt (Read-Host -AsSecureString) and passed by API/stdin —
  never on the command line. Keys are only ever sent to cloud.tenable.com over TLS.
#>

Set-StrictMode -Version Latest
$script:ServiceName = 'tenable-io'
$script:BaseUrl     = 'https://cloud.tenable.com'
$script:Session     = $null   # @{ AccessKey; SecretKey; BaseUrl } after Connect-TenableIO

# ── helpers ──────────────────────────────────────────────────────────────
function ConvertFrom-TIOSecure {
    param([System.Security.SecureString]$Secure)
    if (-not $Secure) { return '' }
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try   { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

function Get-TIODataDir {
    if ($IsWindows) { return (Join-Path $env:LOCALAPPDATA 'tio_client') }
    $base = if ($env:XDG_DATA_HOME) { $env:XDG_DATA_HOME } else { Join-Path $HOME '.local/share' }
    return (Join-Path $base 'tio_client')
}
function Get-TIOKeyFile { Join-Path (Get-TIODataDir) 'keys.json' }

# Vault command hook — run $env:<name> and use its stdout as the key. Nothing is written to disk.
function Invoke-TIOKeyCommand {
    param([string]$EnvName)
    $cmd = [Environment]::GetEnvironmentVariable($EnvName)
    if ([string]::IsNullOrWhiteSpace($cmd)) { return '' }
    try {
        if ($IsWindows) { $out = & $env:ComSpec /c $cmd 2>$null }
        else            { $out = & '/bin/sh' -c $cmd 2>$null }
        if ($LASTEXITCODE -eq 0 -and $out) { return (($out -join "`n").Trim()) }
        Write-Warning "$EnvName exited with code $LASTEXITCODE"
    } catch { Write-Warning "$EnvName failed: $_" }
    return ''
}

# ── OS secret store ──────────────────────────────────────────────────────
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
function Test-TIOFileSafe {
    param([string]$Path)
    if ($IsWindows) { return $true }
    try {
        $mode = (Get-Item -LiteralPath $Path -Force).UnixFileMode
        $loose = [System.IO.UnixFileMode]'GroupRead,GroupWrite,GroupExecute,OtherRead,OtherWrite,OtherExecute'
        if ($mode -band $loose) {
            Write-Warning "Refusing to read $Path — it is group/other-accessible ($mode). Fix: chmod 600 '$Path'"
            return $false
        }
    } catch { return $true }  # can't determine → don't hard-block
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
    param([string]$Account, [string]$Value)
    $dir = Get-TIODataDir
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    if (-not $IsWindows) { try { [System.IO.File]::SetUnixFileMode($dir, [System.IO.UnixFileMode]'UserRead,UserWrite,UserExecute') } catch {} }
    $store = Get-TIOFileStore
    # Windows: encrypt the value at rest with DPAPI (CurrentUser). Unix: store plaintext behind 0600.
    $store[$Account] = if ($IsWindows) { ConvertFrom-SecureString (ConvertTo-SecureString $Value -AsPlainText -Force) } else { $Value }
    $p = Get-TIOKeyFile
    ($store | ConvertTo-Json) | Set-Content -LiteralPath $p -Encoding utf8
    if (-not $IsWindows) { try { [System.IO.File]::SetUnixFileMode($p, [System.IO.UnixFileMode]'UserRead,UserWrite') } catch {} }
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
        if ($IsWindows) { try { return (ConvertFrom-TIOSecure (ConvertTo-SecureString $val)) } catch { return '' } }
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

# Resolve one key: env value → env command → OS store.
function Resolve-TIOKey {
    param([ValidateSet('access','secret')][string]$Account)
    $envValue = if ($Account -eq 'access') { $env:TIO_ACCESS_KEY } else { $env:TIO_SECRET_KEY }
    if ($envValue) { return $envValue }
    $cmdName  = if ($Account -eq 'access') { 'TIO_ACCESS_KEY_CMD' } else { 'TIO_SECRET_KEY_CMD' }
    $fromCmd  = Invoke-TIOKeyCommand $cmdName
    if ($fromCmd) { return $fromCmd }
    return (Get-TIOStoreKey -Account $Account)
}

# ── public API ───────────────────────────────────────────────────────────
function Get-TenableIOKeySource {
    <#.SYNOPSIS Report which credential store this host would use (no secrets shown).#>
    [CmdletBinding()] param()
    $vault = Get-TIOVaultName
    if     ($vault)     { "SecretManagement vault '$vault'" }
    elseif ($IsWindows) { "Windows DPAPI file ($(Get-TIOKeyFile))" }
    else                { "0600 owner-only file ($(Get-TIOKeyFile))" }
}

function Set-TenableIOCredential {
    <#.SYNOPSIS Prompt for the Tenable API access + secret keys and save them to the OS secret store.
       .DESCRIPTION Hidden prompts (entered twice); validates with a session lookup afterwards.#>
    [CmdletBinding()] param([switch]$SkipValidate)
    Write-Host "Storing Tenable API keys in $(Get-TenableIOKeySource) (service '$script:ServiceName')." -ForegroundColor Cyan
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
        $me = Connect-TenableIO -PassThru | ForEach-Object { Get-TenableIOSession }
        Write-Host ("OK — authenticated as {0} ({1}), container {2}." -f $me.username, $me.name, $me.container_id) -ForegroundColor Green
    } catch { Write-Warning "Keys were stored, but validation failed: $_" }
}

function Connect-TenableIO {
    <#.SYNOPSIS Resolve the API keys and stash them for subsequent cmdlets.
       .PARAMETER AccessKey Optional explicit access key (overrides env / store).
       .PARAMETER SecretKey Optional explicit secret key.#>
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
               "  1. Save them:  Set-TenableIOCredential   (uses $(Get-TenableIOKeySource))`n" +
               "  2. Environment: `$env:TIO_ACCESS_KEY / `$env:TIO_SECRET_KEY (or the *_CMD vault hooks)`n" +
               "  3. Connect-TenableIO -AccessKey ... -SecretKey ...`n" +
               "Create a key pair in Tenable: Settings -> My Account -> API Keys.")
    }
    $script:Session = @{ AccessKey = $AccessKey; SecretKey = $SecretKey; BaseUrl = $BaseUrl.TrimEnd('/') }
    if ($PassThru) { [pscustomobject]$script:Session }
}

function Get-TenableIOSession {
    <#.SYNOPSIS Validate the connection — returns your Tenable account (the /session endpoint).#>
    [CmdletBinding()] param()
    if (-not $script:Session) { Connect-TenableIO | Out-Null }
    $headers = @{ 'X-ApiKeys' = "accessKey=$($script:Session.AccessKey);secretKey=$($script:Session.SecretKey)"; 'Accept' = 'application/json' }
    Invoke-RestMethod -Method Get -Uri "$($script:Session.BaseUrl)/session" -Headers $headers
}

Export-ModuleMember -Function Connect-TenableIO, Set-TenableIOCredential, Get-TenableIOSession, Get-TenableIOKeySource
