@{
    RootModule        = 'TenableIO.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = 'b7e4c0a2-9d3f-4a1e-8c6b-2f5a1d7e0c34'
    Author            = 'Joe Cook'
    Copyright         = '(c) 2026 Joe Cook. MIT License.'
    Description       = 'PowerShell client for Tenable Vulnerability Management (Tenable.io / cloud.tenable.com). Runs on Windows PowerShell 5.1 and PowerShell 7+. Cross-platform credential handling: SecretManagement, Windows DPAPI, or a fail-closed 0600 file, with env-var and vault-command hooks. Sibling of tenable-io-python.'
    PowerShellVersion = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    FunctionsToExport = @('Connect-TIO', 'Set-TIOCredential', 'Set-TIOExportDefaults', 'Get-TIOSession',
                          'Get-TIOKeySource', 'Export-TIOFindings', 'Export-TIOAsset',
                          'Export-TIOCompliance', 'Get-TIOScan', 'Get-TIOScanner',
                          'Get-TIOAgent', 'Get-TIOAgentGroup', 'Get-TIOTag',
                          'Get-TIOPolicy', 'Get-TIONetwork', 'Get-TIOExclusion',
                          'Get-TIOUser', 'Get-TIOGroup', 'Get-TIOServerStatus')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @('Export-TIOVuln')
    PrivateData = @{
        PSData = @{
            Tags       = @('Tenable', 'TenableIO', 'VulnerabilityManagement', 'Security', 'InfoSec', 'API')
            LicenseUri = 'https://github.com/cloudanimal/tenable-io-powershell/blob/main/LICENSE'
            ProjectUri = 'https://github.com/cloudanimal/tenable-io-powershell'
        }
    }
}
