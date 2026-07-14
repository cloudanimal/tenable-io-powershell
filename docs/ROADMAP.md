# tenable-io-powershell — API coverage roadmap

A map of the **Tenable Vulnerability Management (Tenable.io) API** translated into a PowerShell
module. Organized by API domain, using approved PowerShell verbs and a consistent `-TIO` noun
prefix.

**Status:** ✅ shipped · ⬜ planned · 🔜 next tranche (highest value)

## Conventions
- `Get-*` = read-only. `New` / `Set` / `Remove` / `Start` / `Stop` / `Import` / `Export` / `Add` /
  `Move` … = state-changing, and every destructive one takes `-WhatIf` / `-Confirm`.
- Pipeline-friendly: `Get-TIOScan | Start-TIOScan`.
- `Invoke-TIORequest` is the generic escape hatch, so any endpoint not yet wrapped is still reachable.

---

## 1. Connection & platform
- ✅ `Connect-TIO` · `Set-TIOCredential` · `Get-TIOKeySource` · `Get-TIOSession` (whoami) · `Get-TIOServerStatus`
- ⬜ `Disconnect-TIO` · `Test-TIOConnection` · `Get-TIOServerProperties` · `Invoke-TIORequest`

## 2. Bulk exports (async: start -> poll -> chunks)
- ✅ `Export-TIOVuln` · `Export-TIOAsset` · `Export-TIOCompliance`
- ⬜ `Get-TIOExportStatus` · `Stop-TIOExport` (cancel)

## 3. Workbenches (fast interactive queries, no full export) 🔜
- ⬜ `Get-TIOVulnerability` (by filter) · `Get-TIOVulnerabilityInfo` (plugin detail) · `Get-TIOVulnerabilityOutput`
- ⬜ `Get-TIOWorkbenchAsset` · `Get-TIOAssetInfo` · `Get-TIOAssetVulnerability`
- ⬜ `Get-TIOFilter` (available vuln/asset/scan filters)

## 4. Assets
- ⬜ `Get-TIOAsset` (list/detail) · `Remove-TIOAsset` (single + bulk)
- ⬜ `Import-TIOAsset` · `Move-TIOAsset` (between networks) · `Get-TIOAssetActivity`

## 5. Scans 🔜
- ✅ `Get-TIOScan`
- ⬜ `New-TIOScan` · `Set-TIOScan` · `Remove-TIOScan` · `Copy-TIOScan`
- ⬜ `Start-TIOScan` (launch) · `Stop-TIOScan` · `Suspend-TIOScan` (pause) · `Resume-TIOScan`
- ⬜ `Get-TIOScanHistory` · `Get-TIOScanStatus`
- ⬜ `Export-TIOScanResult` (download .nessus / CSV / PDF) · `Import-TIONessusFile` (upload results)
- ⬜ `Set-TIOScanSchedule`

## 6. Scan policies & templates
- ✅ `Get-TIOPolicy`
- ⬜ `New-TIOPolicy` · `Set-TIOPolicy` · `Remove-TIOPolicy` · `Copy-TIOPolicy`
- ⬜ `Import-TIOPolicy` · `Export-TIOPolicy`
- ⬜ `Get-TIOScanTemplate` · `Get-TIOPolicyTemplate`

## 7. Scanners & scanner groups
- ✅ `Get-TIOScanner`
- ⬜ `Get-TIOScannerGroup` · `New/Set/Remove-TIOScannerGroup` · `Add/Remove-TIOScannerToGroup`
- ⬜ `Get-TIOScannerKey`

## 8. Agents & agent groups (coverage / hygiene) 🔜
- ✅ `Get-TIOAgent` · `Get-TIOAgentGroup`
- ⬜ `Remove-TIOAgent` (unlink stale)
- ⬜ `New/Set/Remove-TIOAgentGroup` · `Add/Remove-TIOAgentToGroup`
- ⬜ `Get/Set-TIOAgentConfig` · `Get/New/Remove-TIOAgentExclusion` (blackout windows)

## 9. Tags 🔜
- ✅ `Get-TIOTag` (values)
- ⬜ `Get-TIOTagCategory` · `New/Set/Remove-TIOTag` · `New/Remove-TIOTagCategory`
- ⬜ `Add-TIOAssetTag` / `Remove-TIOAssetTag` (bulk assignment) · `Get-TIOTagAssignment`

## 10. Networks, target groups, access groups
- ✅ `Get-TIONetwork`
- ⬜ `New/Set/Remove-TIONetwork` · `Get-TIONetworkAssetCount`
- ⬜ `Get/New/Set/Remove-TIOTargetGroup`
- ⬜ `Get/New/Set/Remove-TIOAccessGroup`

## 11. Exclusions (scan windows)
- ✅ `Get-TIOExclusion`
- ⬜ `New/Set/Remove-TIOExclusion` · `Import-TIOExclusion`

## 12. Managed credentials (for scans)
- ⬜ `Get/New/Set/Remove-TIOManagedCredential` · `Get-TIOCredentialType` · `Get-TIOCredentialPermission`

## 13. Plugins
- ⬜ `Find-TIOPlugin` (paged catalog) · `Get-TIOPlugin` (by ID)
- ⬜ `Get-TIOPluginFamily` · `Get-TIOPluginFamilyDetail`

## 14. Users, groups, roles, permissions *(admin key)*
- ✅ `Get-TIOUser` · `Get-TIOGroup`
- ⬜ `New/Set/Remove-TIOUser` · `Enable/Disable-TIOUser` · `Set-TIOUserRole` · `Set-TIOUserPassword` · `Set-TIOUserAuthorization` (API/UI/SSO)
- ⬜ `New/Set/Remove-TIOGroup` · `Add/Remove-TIOUserToGroup` · `Get-TIOPermission`

## 15. Folders
- ⬜ `Get/New/Set/Remove-TIOFolder`

## 16. Risk workflow — recast / accept-risk / VPR *(admin)*
- ⬜ `Get/New/Set/Remove-TIORecastRule` · `Get/New/Set/Remove-TIOAcceptRiskRule`

## 17. Files
- ⬜ `Send-TIOFile` (upload, for policy/scan import)

## 18. Audit log *(admin)*
- ⬜ `Get-TIOAuditLog`

---

## Optional / larger sub-domains (phase later, possibly separate sub-modules)
- **19. Lumin / Exposure (if licensed):** `Get-TIOExposureScore` · `Get-TIOAssetExposure` · `Get/Set-TIOAcr` (asset criticality) · `Get-TIORemediation`
- **20. Web App Scanning (WAS v2):** its own noun space — `Get/New/Start/Stop-TIOWasScan` · `Get-TIOWasScanResult` · `Get-TIOWasVulnerability` · `Get/Set-TIOWasConfig`
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
