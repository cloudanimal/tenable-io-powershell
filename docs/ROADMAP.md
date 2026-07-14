# tenable-io-powershell — API coverage roadmap

A map of the **Tenable Vulnerability Management (Tenable.io) API** translated into a PowerShell
module. Organized by API domain, using approved PowerShell verbs and a consistent `-TenableIO` noun
prefix.

**Status:** ✅ shipped · ⬜ planned · 🔜 next tranche (highest value)

## Conventions
- `Get-*` = read-only. `New` / `Set` / `Remove` / `Start` / `Stop` / `Import` / `Export` / `Add` /
  `Move` … = state-changing, and every destructive one takes `-WhatIf` / `-Confirm`.
- Pipeline-friendly: `Get-TenableIOScan | Start-TenableIOScan`.
- `Invoke-TenableIORequest` is the generic escape hatch, so any endpoint not yet wrapped is still reachable.

---

## 1. Connection & platform
- ✅ `Connect-TenableIO` · `Set-TenableIOCredential` · `Get-TenableIOKeySource` · `Get-TenableIOSession` (whoami) · `Get-TenableIOServerStatus`
- ⬜ `Disconnect-TenableIO` · `Test-TenableIOConnection` · `Get-TenableIOServerProperties` · `Invoke-TenableIORequest`

## 2. Bulk exports (async: start -> poll -> chunks)
- ✅ `Export-TenableIOVuln` · `Export-TenableIOAsset` · `Export-TenableIOCompliance`
- ⬜ `Get-TenableIOExportStatus` · `Stop-TenableIOExport` (cancel)

## 3. Workbenches (fast interactive queries, no full export) 🔜
- ⬜ `Get-TenableIOVulnerability` (by filter) · `Get-TenableIOVulnerabilityInfo` (plugin detail) · `Get-TenableIOVulnerabilityOutput`
- ⬜ `Get-TenableIOWorkbenchAsset` · `Get-TenableIOAssetInfo` · `Get-TenableIOAssetVulnerability`
- ⬜ `Get-TenableIOFilter` (available vuln/asset/scan filters)

## 4. Assets
- ⬜ `Get-TenableIOAsset` (list/detail) · `Remove-TenableIOAsset` (single + bulk)
- ⬜ `Import-TenableIOAsset` · `Move-TenableIOAsset` (between networks) · `Get-TenableIOAssetActivity`

## 5. Scans 🔜
- ✅ `Get-TenableIOScan`
- ⬜ `New-TenableIOScan` · `Set-TenableIOScan` · `Remove-TenableIOScan` · `Copy-TenableIOScan`
- ⬜ `Start-TenableIOScan` (launch) · `Stop-TenableIOScan` · `Suspend-TenableIOScan` (pause) · `Resume-TenableIOScan`
- ⬜ `Get-TenableIOScanHistory` · `Get-TenableIOScanStatus`
- ⬜ `Export-TenableIOScanResult` (download .nessus / CSV / PDF) · `Import-TenableIONessusFile` (upload results)
- ⬜ `Set-TenableIOScanSchedule`

## 6. Scan policies & templates
- ✅ `Get-TenableIOPolicy`
- ⬜ `New-TenableIOPolicy` · `Set-TenableIOPolicy` · `Remove-TenableIOPolicy` · `Copy-TenableIOPolicy`
- ⬜ `Import-TenableIOPolicy` · `Export-TenableIOPolicy`
- ⬜ `Get-TenableIOScanTemplate` · `Get-TenableIOPolicyTemplate`

## 7. Scanners & scanner groups
- ✅ `Get-TenableIOScanner`
- ⬜ `Get-TenableIOScannerGroup` · `New/Set/Remove-TenableIOScannerGroup` · `Add/Remove-TenableIOScannerToGroup`
- ⬜ `Get-TenableIOScannerKey`

## 8. Agents & agent groups (coverage / hygiene) 🔜
- ✅ `Get-TenableIOAgent` · `Get-TenableIOAgentGroup`
- ⬜ `Remove-TenableIOAgent` (unlink stale)
- ⬜ `New/Set/Remove-TenableIOAgentGroup` · `Add/Remove-TenableIOAgentToGroup`
- ⬜ `Get/Set-TenableIOAgentConfig` · `Get/New/Remove-TenableIOAgentExclusion` (blackout windows)

## 9. Tags 🔜
- ✅ `Get-TenableIOTag` (values)
- ⬜ `Get-TenableIOTagCategory` · `New/Set/Remove-TenableIOTag` · `New/Remove-TenableIOTagCategory`
- ⬜ `Add-TenableIOAssetTag` / `Remove-TenableIOAssetTag` (bulk assignment) · `Get-TenableIOTagAssignment`

## 10. Networks, target groups, access groups
- ✅ `Get-TenableIONetwork`
- ⬜ `New/Set/Remove-TenableIONetwork` · `Get-TenableIONetworkAssetCount`
- ⬜ `Get/New/Set/Remove-TenableIOTargetGroup`
- ⬜ `Get/New/Set/Remove-TenableIOAccessGroup`

## 11. Exclusions (scan windows)
- ✅ `Get-TenableIOExclusion`
- ⬜ `New/Set/Remove-TenableIOExclusion` · `Import-TenableIOExclusion`

## 12. Managed credentials (for scans)
- ⬜ `Get/New/Set/Remove-TenableIOManagedCredential` · `Get-TenableIOCredentialType` · `Get-TenableIOCredentialPermission`

## 13. Plugins
- ⬜ `Find-TenableIOPlugin` (paged catalog) · `Get-TenableIOPlugin` (by ID)
- ⬜ `Get-TenableIOPluginFamily` · `Get-TenableIOPluginFamilyDetail`

## 14. Users, groups, roles, permissions *(admin key)*
- ✅ `Get-TenableIOUser` · `Get-TenableIOGroup`
- ⬜ `New/Set/Remove-TenableIOUser` · `Enable/Disable-TenableIOUser` · `Set-TenableIOUserRole` · `Set-TenableIOUserPassword` · `Set-TenableIOUserAuthorization` (API/UI/SSO)
- ⬜ `New/Set/Remove-TenableIOGroup` · `Add/Remove-TenableIOUserToGroup` · `Get-TenableIOPermission`

## 15. Folders
- ⬜ `Get/New/Set/Remove-TenableIOFolder`

## 16. Risk workflow — recast / accept-risk / VPR *(admin)*
- ⬜ `Get/New/Set/Remove-TenableIORecastRule` · `Get/New/Set/Remove-TenableIOAcceptRiskRule`

## 17. Files
- ⬜ `Send-TenableIOFile` (upload, for policy/scan import)

## 18. Audit log *(admin)*
- ⬜ `Get-TenableIOAuditLog`

---

## Optional / larger sub-domains (phase later, possibly separate sub-modules)
- **19. Lumin / Exposure (if licensed):** `Get-TenableIOExposureScore` · `Get-TenableIOAssetExposure` · `Get/Set-TenableIOAcr` (asset criticality) · `Get-TenableIORemediation`
- **20. Web App Scanning (WAS v2):** its own noun space — `Get/New/Start/Stop-TenableIOWasScan` · `Get-TenableIOWasScanResult` · `Get-TenableIOWasVulnerability` · `Get/Set-TenableIOWasConfig`
- **21. Container / Cloud security:** likely a separate module entirely — flag, don't fold in.

---

## Scale & sequencing
- A "complete" translation is roughly **110–140 cmdlets** — the VM API is large — but it maps cleanly since
  ~80% is CRUD over the resources above.
- **Shipped today: ~18** cmdlets (the ✅'s) — session, the three exports, and the read side of config/inventory.
- **Next tranche (🔜, small + high payoff):** Scans (§5 launch/stop/download), Agent hygiene (§8 unlink stale),
  Tags (§9), and Workbenches (§3 fast queries without a full export).
- **Defer:** admin-key-only areas (§14/§16/§18) and licensed/separate products (Lumin, WAS, Cloud) until there's
  a use case — a Scan Manager key can't exercise most of them anyway.

Sibling: [tenable-io-python](https://github.com/cloudanimal/tenable-io-python).
