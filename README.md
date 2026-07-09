# tenable-io-powershell

A PowerShell client / exporter for **Tenable Vulnerability Management**
(Tenable.io · `cloud.tenable.com`) — pull vulnerabilities, assets, compliance
findings, and the config/inventory endpoints straight from the API.

> **Status: in development.** This is the PowerShell sibling of
> [`tenable-io-python`](https://github.com/cloudanimal/tenable-io-python).

## Tenable.io client family

Same exporter, in the language you reach for:

| Language | Repo |
| --- | --- |
| Python | [tenable-io-python](https://github.com/cloudanimal/tenable-io-python) |
| PowerShell | **tenable-io-powershell** (this repo) |

## Planned

- `Connect-TenableIO` / credential resolution: parameter → environment
  (`TIO_ACCESS_KEY` / `TIO_SECRET_KEY`) → SecretManagement vault.
- Export cmdlets for vulns, assets, and compliance via the async export APIs
  (start → poll → download chunks), streamed so memory stays flat.
- Config/inventory readers (scanners, agents, tags, scan policies, …).
- Guardrails for large pulls (free-disk check, date-scoped compliance).

## Auth

Tenable uses static API key pairs, sent in one header:

```
X-ApiKeys: accessKey=<ACCESS_KEY>;secretKey=<SECRET_KEY>
```

Create a key pair in the Tenable UI under **Settings → My Account → API Keys**.
Keys are never hardcoded — they're read from a parameter, the environment, or a
SecretManagement vault at run time, and only ever sent to `cloud.tenable.com`
over TLS.

## License

MIT — see [LICENSE](LICENSE).
