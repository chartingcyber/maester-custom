function Test-ResCrossTenantInboundTrust {
    <#
    .SYNOPSIS
    Checks that the default cross-tenant access settings do not accept MFA or device claims from other organizations.

    .DESCRIPTION
    By default, when a user from another Microsoft Entra tenant signs in to this tenant, this tenant asks for MFA and
    device checks again. If the default inbound trust settings accept MFA, compliant device or hybrid joined device
    claims from external tenants, an attacker who controls any tenant can mint a guest sign-in that satisfies your
    Conditional Access policies. The check fails when any of the three inbound trust settings is on in the default
    configuration. Partner-specific settings that trust claims from named tenants are listed for review.
    #>
    [MaesterTest(
        Id           = 'MP.RESOURCIVE.3003',
        Title        = 'The default cross-tenant settings do not trust MFA or device claims from external tenants.',
        Product      = 'entra',
        Feature      = 'external-identities',
        Area         = 'external-access',
        ResourceType = 'Tenant',
        Severity     = 'High',
        UserImpact   = 'Low',
        ImplementationCost = 'Low',
        Mitre        = ('T1199', 'T1078.004'),
        Control      = ('nist-800-53-r5:AC-20', 'nist-800-53-r5:IA-2'),
        Service      = 'Graph',
        Permission   = 'Graph:Scope:Policy.Read.All'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    try {
        $default = Invoke-MtGraphRequest -RelativeUri 'policies/crossTenantAccessPolicy/default' -ApiVersion v1.0 -ErrorAction Stop
        $partners = @(Invoke-MtGraphRequest -RelativeUri 'policies/crossTenantAccessPolicy/partners' -ApiVersion v1.0 -ErrorAction Stop)
    } catch {
        Resolve-ResGraphError -ErrorRecord $_ -Feature 'cross-tenant access settings' -Requires 'Policy.Read.All'
    }

    $trust = $default.inboundTrust
    $accepted = @()
    if ($trust.isMfaAccepted) { $accepted += 'MFA claims' }
    if ($trust.isCompliantDeviceAccepted) { $accepted += 'compliant device claims' }
    if ($trust.isHybridAzureADJoinedDeviceAccepted) { $accepted += 'hybrid joined device claims' }

    $partnerTrust = @($partners | Where-Object { $_.inboundTrust.isMfaAccepted -or $_.inboundTrust.isCompliantDeviceAccepted -or $_.inboundTrust.isHybridAzureADJoinedDeviceAccepted } | ForEach-Object {
            $claims = @()
            if ($_.inboundTrust.isMfaAccepted) { $claims += 'MFA' }
            if ($_.inboundTrust.isCompliantDeviceAccepted) { $claims += 'compliant device' }
            if ($_.inboundTrust.isHybridAzureADJoinedDeviceAccepted) { $claims += 'hybrid joined device' }
            "$($_.tenantId): $($claims -join ', ')"
        })
    $partnerText = if ($partnerTrust.Count -gt 0) { "`n`nPartner organizations whose claims are trusted (confirm each is a known partner): $($partnerTrust -join '; ')." } else { "`n`nNo partner-specific settings trust external claims." }

    if ($accepted.Count -eq 0) {
        Add-MtTestResultDetail -Result "Well done. The default cross-tenant settings do not accept MFA or device claims from external tenants.$partnerText"
        return $true
    }
    Add-MtTestResultDetail -Result "The default cross-tenant settings accept $($accepted -join ', ') from every external tenant.$partnerText"
    return $false
}
