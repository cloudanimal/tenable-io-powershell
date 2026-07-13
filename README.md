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
Set-TenableIOCredential    # hidden prompts for your access + secret key, saves to the OS store
Connect-TenableIO          # resolves the keys for this session
Get-TenableIOSession       # validate — returns your Tenable account
```

Create a key pair in Tenable under **Settings → My Account → API Keys**.

## Export data

Each export runs Tenable's async export flow (start → poll → download chunks) and **streams** results,
so memory stays flat. With `-Path` it writes JSONL to a file (with a free-disk guard); without `-Path`
it emits objects to the pipeline.

```powershell
# stream straight to a JSONL file
Export-TenableIOVuln -Path ./vulns.jsonl                 # every state (open, reopened, fixed)
Export-TenableIOVuln -State OPEN -Severity high,critical -Path ./open-crit.jsonl
Export-TenableIOAsset -Path ./assets.jsonl
Export-TenableIOCompliance -Since (Get-Date).AddDays(-90) -Path ./compliance.jsonl

# …or work with the objects directly in the pipeline
Export-TenableIOVuln -State OPEN | Where-Object { $_.severity -eq 'critical' } | Measure-Object
```

> Exports can be large. The file writer **aborts if free disk on the target drive drops below 2 GB**,
> and `-Since` on compliance avoids pulling the (often enormous) full audit history.

## Read config & inventory

Read-only cmdlets for the config/inventory endpoints — they return objects, so pipe them anywhere:

```powershell
Get-TenableIOScanner | Select-Object name, status, type
Get-TenableIOScan    | Where-Object status -eq 'running'
Get-TenableIOUser    | Measure-Object

# agents live under the agent-manager scanner (id 1 by default) — great for coverage/hygiene checks
Get-TenableIOAgent | Where-Object { [datetimeoffset]::FromUnixTimeSeconds($_.last_connect).UtcDateTime -lt (Get-Date).AddDays(-30) }
Get-TenableIOAgent -AllScanners       # thorough sweep of every scanner (slower on big tenants)
```

Also: `Get-TenableIOAgentGroup`, `-Tag`, `-Policy`, `-Network`, `-Exclusion`, `-Group`, `-ServerStatus`.

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
| Windows | **DPAPI-encrypted file** (per-user, encrypted at rest) |
| Linux / macOS | a **`0600` owner-only file** — the read is refused unless it's owner-only (**fail closed**) |

`Get-TenableIOKeySource` prints which store this host will use (no secrets shown).

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
| `Set-TenableIOCredential` | ✅ | Prompt for + store the API keys; validate. |
| `Connect-TenableIO` | ✅ | Resolve keys for the session. |
| `Get-TenableIOSession` | ✅ | Validate the connection (the `/session` endpoint). |
| `Get-TenableIOKeySource` | ✅ | Report which credential store is in use. |
| `Export-TenableIOVuln` | ✅ | Vulnerability findings (state / severity / since filters). |
| `Export-TenableIOAsset` | ✅ | Assets (hosts) with attributes, tags, sources. |
| `Export-TenableIOCompliance` | ✅ | Compliance findings (use `-Since` to bound the history). |
| `Get-TenableIOScan` / `-Scanner` / `-Policy` / `-Network` / `-Exclusion` / `-User` / `-Group` / `-ServerStatus` | ✅ | Config & inventory reads. |
| `Get-TenableIOAgent` / `-AgentGroup` / `-Tag` | ✅ | Agents (with last-connect), agent groups, and tags. |

## License

MIT — see [LICENSE](LICENSE).
