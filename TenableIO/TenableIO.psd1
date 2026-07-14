@{
    RootModule        = 'TenableIO.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = 'b7e4c0a2-9d3f-4a1e-8c6b-2f5a1d7e0c34'
    Author            = 'Joe Cook'
    Copyright         = '(c) 2026 Joe Cook. MIT License.'
    Description       = 'PowerShell client for Tenable Vulnerability Management (Tenable.io / cloud.tenable.com). Runs on Windows PowerShell 5.1 and PowerShell 7+. Cross-platform credential handling: SecretManagement, Windows DPAPI, or a fail-closed 0600 file, with env-var and vault-command hooks. Sibling of tenable-io-python.'
    PowerShellVersion = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    FunctionsToExport = @('Connect-Tio', 'Set-TioCredential', 'Get-TioSession',
                          'Get-TioKeySource', 'Export-TioVuln', 'Export-TioAsset',
                          'Export-TioCompliance', 'Get-TioScan', 'Get-TioScanner',
                          'Get-TioAgent', 'Get-TioAgentGroup', 'Get-TioTag',
                          'Get-TioPolicy', 'Get-TioNetwork', 'Get-TioExclusion',
                          'Get-TioUser', 'Get-TioGroup', 'Get-TioServerStatus')
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
