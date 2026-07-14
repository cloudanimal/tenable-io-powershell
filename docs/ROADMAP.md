# tenable-io-powershell — API coverage roadmap

A map of the **Tenable Vulnerability Management (Tenable.io) API** translated into a PowerShell
module. Organized by API domain, using approved PowerShell verbs and a consistent `-Tio` noun
prefix.

**Status:** ✅ shipped · ⬜ planned · 🔜 next tranche (highest value)

## Conventions
- `Get-*` = read-only. `New` / `Set` / `Remove` / `Start` / `Stop` / `Import` / `Export` / `Add` /
  `Move` … = state-changing, and every destructive one takes `-WhatIf` / `-Confirm`.
- Pipeline-friendly: `Get-TioScan | Start-TioScan`.
- `Invoke-TioRequest` is the generic escape hatch, so any endpoint not yet wrapped is still reachable.

---

## 1. Connection & platform
- ✅ `Connect-Tio` · `Set-TioCredential` · `Get-TioKeySource` · `Get-TioSession` (whoami) · `Get-TioServerStatus`
- ⬜ `Disconnect-Tio` · `Test-TioConnection` · `Get-TioServerProperties` · `Invoke-TioRequest`

## 2. Bulk exports (async: start -> poll -> chunks)
- ✅ `Export-TioVuln` · `Export-TioAsset` · `Export-TioCompliance`
- ⬜ `Get-TioExportStatus` · `Stop-TioExport` (cancel)

## 3. Workbenches (fast interactive queries, no full export) 🔜
- ⬜ `Get-TioVulnerability` (by filter) · `Get-TioVulnerabilityInfo` (plugin detail) · `Get-TioVulnerabilityOutput`
- ⬜ `Get-TioWorkbenchAsset` · `Get-TioAssetInfo` · `Get-TioAssetVulnerability`
- ⬜ `Get-TioFilter` (available vuln/asset/scan filters)

## 4. Assets
- ⬜ `Get-TioAsset` (list/detail) · `Remove-TioAsset` (single + bulk)
- ⬜ `Import-TioAsset` · `Move-TioAsset` (between networks) · `Get-TioAssetActivity`

## 5. Scans 🔜
- ✅ `Get-TioScan`
- ⬜ `New-TioScan` · `Set-TioScan` · `Remove-TioScan` · `Copy-TioScan`
- ⬜ `Start-TioScan` (launch) · `Stop-TioScan` · `Suspend-TioScan` (pause) · `Resume-TioScan`
- ⬜ `Get-TioScanHistory` · `Get-TioScanStatus`
- ⬜ `Export-TioScanResult` (download .nessus / CSV / PDF) · `Import-TioNessusFile` (upload results)
- ⬜ `Set-TioScanSchedule`

## 6. Scan policies & templates
- ✅ `Get-TioPolicy`
- ⬜ `New-TioPolicy` · `Set-TioPolicy` · `Remove-TioPolicy` · `Copy-TioPolicy`
- ⬜ `Import-TioPolicy` · `Export-TioPolicy`
- ⬜ `Get-TioScanTemplate` · `Get-TioPolicyTemplate`

## 7. Scanners & scanner groups
- ✅ `Get-TioScanner`
- ⬜ `Get-TioScannerGroup` · `New/Set/Remove-TioScannerGroup` · `Add/Remove-TioScannerToGroup`
- ⬜ `Get-TioScannerKey`

## 8. Agents & agent groups (coverage / hygiene) 🔜
- ✅ `Get-TioAgent` · `Get-TioAgentGroup`
- ⬜ `Remove-TioAgent` (unlink stale)
- ⬜ `New/Set/Remove-TioAgentGroup` · `Add/Remove-TioAgentToGroup`
- ⬜ `Get/Set-TioAgentConfig` · `Get/New/Remove-TioAgentExclusion` (blackout windows)

## 9. Tags 🔜
- ✅ `Get-TioTag` (values)
- ⬜ `Get-TioTagCategory` · `New/Set/Remove-TioTag` · `New/Remove-TioTagCategory`
- ⬜ `Add-TioAssetTag` / `Remove-TioAssetTag` (bulk assignment) · `Get-TioTagAssignment`

## 10. Networks, target groups, access groups
- ✅ `Get-TioNetwork`
- ⬜ `New/Set/Remove-TioNetwork` · `Get-TioNetworkAssetCount`
- ⬜ `Get/New/Set/Remove-TioTargetGroup`
- ⬜ `Get/New/Set/Remove-TioAccessGroup`

## 11. Exclusions (scan windows)
- ✅ `Get-TioExclusion`
- ⬜ `New/Set/Remove-TioExclusion` · `Import-TioExclusion`

## 12. Managed credentials (for scans)
- ⬜ `Get/New/Set/Remove-TioManagedCredential` · `Get-TioCredentialType` · `Get-TioCredentialPermission`

## 13. Plugins
- ⬜ `Find-TioPlugin` (paged catalog) · `Get-TioPlugin` (by ID)
- ⬜ `Get-TioPluginFamily` · `Get-TioPluginFamilyDetail`

## 14. Users, groups, roles, permissions *(admin key)*
- ✅ `Get-TioUser` · `Get-TioGroup`
- ⬜ `New/Set/Remove-TioUser` · `Enable/Disable-TioUser` · `Set-TioUserRole` · `Set-TioUserPassword` · `Set-TioUserAuthorization` (API/UI/SSO)
- ⬜ `New/Set/Remove-TioGroup` · `Add/Remove-TioUserToGroup` · `Get-TioPermission`

## 15. Folders
- ⬜ `Get/New/Set/Remove-TioFolder`

## 16. Risk workflow — recast / accept-risk / VPR *(admin)*
- ⬜ `Get/New/Set/Remove-TioRecastRule` · `Get/New/Set/Remove-TioAcceptRiskRule`

## 17. Files
- ⬜ `Send-TioFile` (upload, for policy/scan import)

## 18. Audit log *(admin)*
- ⬜ `Get-TioAuditLog`

---

## Optional / larger sub-domains (phase later, possibly separate sub-modules)
- **19. Lumin / Exposure (if licensed):** `Get-TioExposureScore` · `Get-TioAssetExposure` · `Get/Set-TioAcr` (asset criticality) · `Get-TioRemediation`
- **20. Web App Scanning (WAS v2):** its own noun space — `Get/New/Start/Stop-TioWasScan` · `Get-TioWasScanResult` · `Get-TioWasVulnerability` · `Get/Set-TioWasConfig`
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
