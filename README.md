# tenable-io-powershell

A PowerShell client / exporter for **Tenable Vulnerability Management**
(Tenable.io · `cloud.tenable.com`) — pull vulnerabilities, assets, compliance
findings, and the config/inventory endpoints straight from the API.

> **Status: working — credentials + streamed exports.** Sibling of
> [`tenable-io-python`](https://github.com/cloudanimal/tenable-io-python).

## Tenable.io client family

Same exporter, in the language you reach for:

| Language | Repo |
| --- | --- |
| Python | [tenable-io-python](https://github.com/cloudanimal/tenable-io-python) |
| PowerShell | **tenable-io-powershell** (this repo) |

## Install

```powershell
Import-Module ./TenableIO/TenableIO.psd1     # Windows PowerShell 5.1+ or PowerShell 7+
```

Runs on **Windows PowerShell 5.1** (the version built into Windows — nothing to install) and on
**PowerShell 7+** cross-platform. On 5.1 it forces TLS 1.2 for you and stores keys with Windows DPAPI.

## Get started

```powershell
Set-TIOCredential    # hidden prompts for your access + secret key, saves to the OS store
Connect-TIO          # resolves the keys for this session
Get-TIOSession       # validate — returns your Tenable account
```

Create a key pair in Tenable under **Settings → My Account → API Keys**.

## Export data

Each export runs Tenable's async export flow (start → poll → download chunks) and **streams** results,
so memory stays flat. With `-Path` it writes JSONL to a file (with a free-disk guard); without `-Path`
it emits objects to the pipeline.

```powershell
# stream straight to a JSONL file
Export-TIOFindings -Path ./current-findings.jsonl         # default: CURRENT findings (OPEN + REOPENED)
Export-TIOFindings -All -Path ./all-findings.jsonl        # ALL findings incl. FIXED history (large - opt-in)
Export-TIOFindings -State OPEN -Severity high,critical -Path ./open-crit.jsonl
Export-TIOAsset -Path ./assets.jsonl
Export-TIOCompliance -Since "90 days" -Path ./compliance.jsonl

# …or work with the objects directly in the pipeline
Export-TIOFindings -State OPEN | Where-Object { $_.severity -eq 'critical' } | Measure-Object
```

### Smart date ranges with `-Since`

The `-Since` parameter accepts **both absolute datetimes and relative date strings**:

```powershell
# Relative date strings (simpler for common cases)
Export-TIOFindings -Since "14 days"      # last 2 weeks
Export-TIOFindings -Since "7d"           # last 7 days (short form)
Export-TIOFindings -Since "2 weeks"
Export-TIOFindings -Since "1 year"

# Absolute datetime (unchanged)
Export-TIOFindings -Since (Get-Date).AddDays(-30)
Export-TIOFindings -Since "2026-01-01"
```

**Supported relative date formats:**
- Days: `"7 days"`, `"7d"`
- Weeks: `"2 weeks"`, `"2w"`
- Years: `"1 year"`, `"1y"`
- Hours: `"12 hours"`, `"12h"`
- Minutes: `"30 minutes"`, `"30m"`

### Set defaults for your session

Use `Set-TIOExportDefaults` to apply parameter defaults to all `Export-TIOFindings` calls in your session:

```powershell
# Set defaults once
Set-TIOExportDefaults `
    -Severity high,critical `
    -State OPEN,REOPENED `
    -Since "14 days" `
    -Path "C:\TIO_Exports"

# Now all exports use these defaults
Export-TIOFindings                   # uses all defaults
Export-TIOFindings -Severity info    # overrides severity, keeps others
```

Defaults persist only for the current session. To make them permanent, add the call to your PowerShell profile.

### Targeted pulls (filters applied server-side)

`Export-TIOFindings` filters are sent to Tenable, so **only the matching slice is transferred** — no
downloading everything and grepping locally:

```powershell
# critical, high-VPR findings on one business unit → the "fix these now" list
Export-TIOFindings -Severity critical -VprMin 9 -Tag @{ BU = 'AMI' } -Path ./crown-jewels-crit.jsonl

# everything a specific plugin or plugin family reports, within a CIDR
Export-TIOFindings -PluginId 51192,57582 -Cidr 10.20.0.0/16 -Path ./cert-issues.jsonl
Export-TIOFindings -PluginFamily 'Windows' -Severity high,critical

# scope to a network and a VPR band
Export-TIOFindings -NetworkId 00000000-0000-0000-0000-000000000000 -VprMin 7 -VprMax 8.9
```

| Filter | Parameter |
| --- | --- |
| State | `-All` · `-State OPEN,REOPENED,FIXED` |
| Severity | `-Severity info,low,medium,high,critical` |
| Risk (VPR) | `-VprMin` / `-VprMax` (0–10) — *the export filters on VPR, not CVSS* |
| Plugin | `-PluginId 19506,…` · `-PluginFamily 'Windows',…` · `-PluginType remote,local,combined,…` |
| Source | `-Source NESSUS,AGENT,NNM` — agent- vs network- vs passively-collected |
| Severity origin | `-SeverityModification NONE,ACCEPTED,RECASTED` — audit accepted-risk / recast findings |
| Network | `-NetworkId <uuid>` · `-Cidr 10.0.0.0/8` |
| Tags | `-Tag @{ BU = 'AMI'; Environment = 'Production','Staging' }` |
| Time | `-Since` (smart datetime/string) · `-FirstFound` · `-LastFound` · `-LastFixed` · `-IndexedSince` |

```powershell
# remediation verification — what was fixed in the last month
Export-TIOFindings -State FIXED -LastFixed "30 days" -Path ./fixed-this-month.jsonl

# governance — everything currently accepted-risk or recast
Export-TIOFindings -SeverityModification ACCEPTED,RECASTED -All

# coverage — only agent-collected high/critical findings from last 7 days
Export-TIOFindings -Source AGENT -Severity high,critical -Since "7d"
```

> **CVSS note:** Tenable's vuln export accepts a VPR range but rejects `cvss_base_score`
> (`BAD_REQUEST_UNKNOWN_PROPERTY`). To slice by CVSS, filter client-side after the pull:
> `Export-TIOFindings -Severity critical | Where-Object { $_.plugin.cvss3_base_score -ge 9 }`.

> Exports can be large. The file writer **aborts if free disk on the target drive drops below 2 GB**,
> and `-Since` on compliance avoids pulling the (often enormous) full audit history.

## Read config & inventory

Read-only cmdlets for the config/inventory endpoints — they return objects, so pipe them anywhere:

```powershell
Get-TIOScanner | Select-Object name, status, type
Get-TIOScan    | Where-Object status -eq 'running'
Get-TIOUser    | Measure-Object

# agents live under the agent-manager scanner (id 1 by default) — great for coverage/hygiene checks
Get-TIOAgent | Where-Object { [datetimeoffset]::FromUnixTimeSeconds($_.last_connect).UtcDateTime -lt (Get-Date).AddDays(-30) }
Get-TIOAgent -AllScanners       # thorough sweep of every scanner (slower on big tenants)
```

Also: `Get-TIOAgentGroup`, `-Tag`, `-Policy`, `-Network`, `-Exclusion`, `-Group`, `-ServerStatus`.

## Credentials

Keys resolve in this order (mirrors [tenable-io-python](https://github.com/cloudanimal/tenable-io-python)):

```
-AccessKey / -SecretKey parameter
  → $env:TIO_ACCESS_KEY / $env:TIO_SECRET_KEY            (value)
  → $env:TIO_ACCESS_KEY_CMD / $env:TIO_SECRET_KEY_CMD    (vault command; stdout is the key)
  → OS secret store
```

The OS secret store is chosen automatically — no key is ever placed on the command line:

| Platform | Store |
| --- | --- |
| Any | `Microsoft.PowerShell.SecretManagement` vault, if one is registered (preferred) |
| Windows | **Windows Credential Manager** entries named `Tenable API - access` / `Tenable API - secret` |
| Linux / macOS | a **`0600` owner-only file** — the read is refused unless it's owner-only (**fail closed**) |

`Get-TIOKeySource` prints which store this host will use (no secrets shown).

### Headless servers (RHEL, CI) — pull from your vault

Don't store keys on the box; fetch them at run time. Both options outrank the local store:

```powershell
# a) inject env vars from your secrets manager (CI secret, systemd LoadCredential, …)
$env:TIO_ACCESS_KEY = '...'; $env:TIO_SECRET_KEY = '...'

# b) point the client at your vault — its stdout is used as the key, nothing is written to disk
$env:TIO_ACCESS_KEY_CMD = 'vault kv get -field=access secret/tenable'
$env:TIO_SECRET_KEY_CMD = 'vault kv get -field=secret secret/tenable'
```

Auth uses static API key pairs, sent in one header (`X-ApiKeys: accessKey=…;secretKey=…`) and only
ever to `cloud.tenable.com` over TLS.

## Cmdlets

| Cmdlet | Status | Purpose |
| --- | --- | --- |
| `Set-TIOCredential` | ✅ | Prompt for + store the API keys; validate. |
| `Connect-TIO` | ✅ | Resolve keys for the session. |
| `Get-TIOSession` | ✅ | Validate the connection (the `/session` endpoint). |
| `Get-TIOKeySource` | ✅ | Report which credential store is in use. |
| `Export-TIOFindings` | ✅ | Vulnerability findings (state / severity / since filters). Alias: `Export-TIOVuln`. |
| `Set-TIOExportDefaults` | ✅ | Set session-level defaults for `Export-TIOFindings` parameters. |
| `ConvertTo-TIORelativeDate` | ✅ | Parse relative date strings (e.g., "7 days", "7d") into datetime objects. |
| `Export-TIOAsset` | ✅ | Assets (hosts) with attributes, tags, sources. |
| `Export-TIOCompliance` | ✅ | Compliance findings (use `-Since` to bound the history). |
| `Get-TIOScan` / `-Scanner` / `-Policy` / `-Network` / `-Exclusion` / `-User` / `-Group` / `-ServerStatus` | ✅ | Config & inventory reads. |
| `Get-TIOAgent` / `-AgentGroup` / `-Tag` | ✅ | Agents (with last-connect), agent groups, and tags. |

See **[docs/ROADMAP.md](docs/ROADMAP.md)** for the full Tenable VM API-coverage roadmap (what's shipped and what's planned, by domain).

## License

MIT — see [LICENSE](LICENSE).
