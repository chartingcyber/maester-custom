function Test-ResEntraLapsEnabled {
    <#
    .SYNOPSIS
    Checks that Windows LAPS is enabled in Microsoft Entra, so that devices can back up their local administrator password.

    .DESCRIPTION
    Reads the device registration policy and passes when localAdminPassword.isEnabled is true. An Intune LAPS policy
    that backs up to Entra ID does nothing for Entra joined devices until this tenant setting is on.
    Windows LAPS is free; it needs Entra ID Free or higher.
    #>
    [MaesterTest(
        Id           = 'MP.RESOURCIVE.1001',
        Title        = 'Windows LAPS is enabled in Microsoft Entra.',
        Product      = 'entra',
        RelatedProduct = 'intune',
        Feature      = 'devices',
        Area         = 'privileged-access',
        ResourceType = 'Tenant',
        Severity     = 'Medium',
        UserImpact   = 'Low',
        ImplementationCost = 'Low',
        Mitre        = ('T1078.003', 'T1550.002'),
        Control      = 'nist-800-53-r5:IA-5',
        Service      = 'Graph',
        Permission   = 'Graph:Scope:Policy.Read.All'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    try {
        $policy = Invoke-MtGraphRequest -RelativeUri 'policies/deviceRegistrationPolicy' -ApiVersion beta -ErrorAction Stop
    } catch {
        Resolve-ResGraphError -ErrorRecord $_ -Feature 'the device registration policy' -Requires 'Policy.Read.All'
    }

    $enabled = [bool]$policy.localAdminPassword.isEnabled
    if ($enabled) {
        Add-MtTestResultDetail -Result 'Well done. Windows LAPS is enabled in Microsoft Entra, so Entra joined devices can back up their local administrator password to Entra ID.'
    } else {
        Add-MtTestResultDetail -Result "Windows LAPS is not enabled in Microsoft Entra. Entra joined devices cannot back up the local administrator password to Entra ID, even when an Intune LAPS policy asks them to.`n`nEnable it under **Entra ID** > **Devices** > **Device settings** > **Enable Microsoft Entra Local Administrator Password Solution (LAPS)**."
    }
    return $enabled
}
