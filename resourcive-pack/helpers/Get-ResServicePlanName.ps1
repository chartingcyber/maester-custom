function Get-ResServicePlanName {
    <#
    .SYNOPSIS
    Returns the Microsoft service plan names that mean a tenant holds a product, for Assert-ResLicense and Test-ResLicense.

    .DESCRIPTION
    Names were checked against the Microsoft Learn list "Product names and service plan identifiers for licensing".
    - Intune: Intune Plan 1 and its government, volume and education variants.
    - DefenderEndpoint: Defender for Business (in Microsoft 365 Business Premium), Defender for Endpoint Plan 1 and Plan 2.
    - EntraP1: Entra ID P1 or P2 (Conditional Access, authentication strengths, sign-in logs through Graph).
    - EntraP2: Entra ID P2 or Entra ID Governance (ID Protection risk, PIM).
    - DefenderOffice: Defender for Office 365 Plan 1 or Plan 2.
    - Exchange: any Exchange Online mailbox plan.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        # The product.
        [Parameter(Mandatory)]
        [ValidateSet('Intune', 'DefenderEndpoint', 'EntraP1', 'EntraP2', 'DefenderOffice', 'Exchange')]
        [string] $Product
    )

    switch ($Product) {
        'Intune' { 'INTUNE_A', 'INTUNE_A_GOV', 'INTUNE_A_VL', 'INTUNE_EDU' }
        'DefenderEndpoint' { 'MDE_SMB', 'MDE_LITE', 'WINDEFATP' }
        'EntraP1' { 'AAD_PREMIUM', 'AAD_PREMIUM_P2' }
        'EntraP2' { 'AAD_PREMIUM_P2', 'Entra_Identity_Governance' }
        'DefenderOffice' { 'ATP_ENTERPRISE', 'THREAT_INTELLIGENCE' }
        'Exchange' { 'EXCHANGE_S_ENTERPRISE', 'EXCHANGE_S_STANDARD', 'EXCHANGE_S_ENTERPRISE_GOV', 'EXCHANGE_S_DESKLESS' }
    }
}
