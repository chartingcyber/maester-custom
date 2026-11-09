function Test-ResUnmanagedJoinedDevices {
    <#
    .SYNOPSIS
    Checks for Entra joined or hybrid joined devices that are not managed by Intune but have signed in recently.

    .DESCRIPTION
    A device that is joined to the directory but not managed has no compliance policy, no encryption policy and no
    attack surface rules, and it still receives the user's tokens. This reads the Entra device list and reports
    joined devices (trust type AzureAd or ServerAd) with isManaged not true and a sign-in within RecentDays. Devices
    that are only registered (BYOD, trust type Workplace) are left out unless IncludeRegistered is set. Servers
    that are joined and intentionally unmanaged by Intune can be excluded with ExcludedOperatingSystems.
    #>
    [MaesterTest(
        Id           = 'MP.RESOURCIVE.1012',
        Title        = 'No joined device that signed in recently is unmanaged.',
        Product      = 'entra',
        RelatedProduct = 'intune',
        Feature      = 'devices',
        Area         = 'devices',
        ResourceType = 'Device',
        Severity     = 'Medium',
        UserImpact   = 'Medium',
        ImplementationCost = 'Medium',
        Mitre        = ('T1078', 'T1133'),
        Control      = ('nist-800-53-r5:CM-8'),
        Service      = 'Graph',
        Permission   = 'Graph:Scope:Device.Read.All'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        # Only devices that signed in within this many days are counted.
        [ValidateRange(1, 365)]
        [int] $RecentDays = 30,

        # Also count devices that are only registered (BYOD), not joined.
        [switch] $IncludeRegistered,

        # Operating systems to leave out, for example Linux.
        [string[]] $ExcludedOperatingSystems = @()
    )

    try {
        $devices = @(Invoke-MtGraphRequest -RelativeUri 'devices' -ApiVersion v1.0 -Select id, displayName, operatingSystem, trustType, isManaged, isCompliant, approximateLastSignInDateTime, accountEnabled -ErrorAction Stop)
    } catch {
        Resolve-ResGraphError -ErrorRecord $_ -Feature 'Entra devices' -Requires 'Device.Read.All'
    }

    $since = (Get-Date).ToUniversalTime().AddDays(-$RecentDays)
    # Printers and computer accounts (names ending in $) are directory objects, not endpoints Intune could manage.
    $candidates = @($devices | Where-Object {
            $_.accountEnabled -ne $false -and
            $_.isManaged -ne $true -and
            $_.approximateLastSignInDateTime -and ([datetime]$_.approximateLastSignInDateTime).ToUniversalTime() -ge $since -and
            ($IncludeRegistered -or $_.trustType -in @('AzureAd', 'ServerAd')) -and
            $_.operatingSystem -notin $ExcludedOperatingSystems -and
            $_.operatingSystem -ne 'Printer' -and
            ([string]$_.displayName) -notmatch '\$$'
        })
    # Hybrid joined devices are often managed by Configuration Manager or Group Policy, which Entra cannot see.
    $hybrid = @($candidates | Where-Object { $_.trustType -eq 'ServerAd' })
    $unmanaged = @($candidates | Where-Object { $_.trustType -ne 'ServerAd' })

    $asOf = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm')
    if ($candidates.Count -eq 0) {
        Add-MtTestResultDetail -Result "Well done. No $(if ($IncludeRegistered) { 'registered or ' })joined device that signed in during the last $RecentDays days is unmanaged. Read $($devices.Count) devices as of $asOf UTC. Printers and computer accounts are left out."
        return $true
    }

    function Get-DeviceTable {
        param($Device)
        $text = "| Device | Operating system | Join type | Last sign-in |`n| --- | --- | --- | --- |`n" +
            ((@($Device) | Sort-Object { $_.approximateLastSignInDateTime } -Descending | Select-Object -First 50 | ForEach-Object { "| $($_.displayName) | $($_.operatingSystem) | $($_.trustType) | $($_.approximateLastSignInDateTime) |" }) -join "`n")
        if (@($Device).Count -gt 50) { $text += "`n`nThe first 50 of $(@($Device).Count) devices are shown." }
        $text
    }

    $hybridText = if ($hybrid.Count -gt 0) { "`n`n**$($hybrid.Count) hybrid joined device(s)** are not managed by Intune. They may be managed by Configuration Manager or Group Policy, which Entra cannot see, so confirm that each is.`n`n$(Get-DeviceTable $hybrid)" } else { '' }

    if ($unmanaged.Count -eq 0) {
        Add-MtTestResultDetail -Result "Only hybrid joined devices are not managed by Intune. Read $($devices.Count) devices as of $asOf UTC.$hybridText" -Investigate
        return $false
    }
    Add-MtTestResultDetail -Result "$($unmanaged.Count) cloud joined or registered device(s) signed in during the last $RecentDays days and are not managed by Intune. Read $($devices.Count) devices as of $asOf UTC.`n`n$(Get-DeviceTable $unmanaged)$hybridText"
    return $false
}
