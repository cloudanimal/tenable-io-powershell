# tenable-io-powershell

A PowerShell client / exporter for **Tenable Vulnerability Management**
(Tenable.io · `cloud.tenable.com`) — pull vulnerabilities, assets, compliance
findings, and the config/inventory endpoints straight from the API.

> **Status: credential layer shipped; export cmdlets in progress.** Sibling of
> [`tenable-io-python`](https://github.com/cloudanimal/tenable-io-python).

## Tenable.io client family

Same exporter, in the language you reach for:

| Language | Repo |
| --- | --- |
| Python | [tenable-io-python](https://github.com/cloudanimal/tenable-io-python) |
| PowerShell | **tenable-io-powershell** (this repo) |

## Install

```powershell
Import-Module ./TenableIO/TenableIO.psd1     # PowerShell 7.3+
```

## Get started

```powershell
Set-TenableIOCredential    # hidden prompts for your access + secret key, saves to the OS store
Connect-TenableIO          # resolves the keys for this session
Get-TenableIOSession       # validate — returns your Tenable account
```

Create a key pair in Tenable under **Settings → My Account → API Keys**.

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
| `Export-TenableIOVuln` / `-Asset` / `-Compliance` | 🔜 | Streamed exports via the async export APIs. |

## License

MIT — see [LICENSE](LICENSE).
