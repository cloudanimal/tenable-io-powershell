@{
    RootModule        = 'TenableIO.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = 'b7e4c0a2-9d3f-4a1e-8c6b-2f5a1d7e0c34'
    Author            = 'Joe Cook'
    Copyright         = '(c) 2026 Joe Cook. MIT License.'
    Description       = 'PowerShell client for Tenable Vulnerability Management (Tenable.io / cloud.tenable.com). Cross-platform credential handling: SecretManagement, Windows DPAPI, or a fail-closed 0600 file, with env-var and vault-command hooks. Sibling of tenable-io-python.'
    PowerShellVersion = '7.3'
    FunctionsToExport = @('Connect-TenableIO', 'Set-TenableIOCredential', 'Get-TenableIOSession',
                          'Get-TenableIOKeySource', 'Export-TenableIOVuln', 'Export-TenableIOAsset',
                          'Export-TenableIOCompliance', 'Get-TenableIOScan', 'Get-TenableIOScanner',
                          'Get-TenableIOAgent', 'Get-TenableIOAgentGroup', 'Get-TenableIOTag',
                          'Get-TenableIOPolicy', 'Get-TenableIONetwork', 'Get-TenableIOExclusion',
                          'Get-TenableIOUser', 'Get-TenableIOGroup', 'Get-TenableIOServerStatus')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData = @{
        PSData = @{
            Tags       = @('Tenable', 'TenableIO', 'VulnerabilityManagement', 'Security', 'InfoSec', 'API')
            LicenseUri = 'https://github.com/cloudanimal/tenable-io-powershell/blob/main/LICENSE'
            ProjectUri = 'https://github.com/cloudanimal/tenable-io-powershell'
        }
    }
}
