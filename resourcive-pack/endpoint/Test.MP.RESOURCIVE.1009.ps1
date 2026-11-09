function Test-ResBitLockerRecoveryKeyEscrow {
    <#
    .SYNOPSIS
    Checks that every encrypted Windows device has a BitLocker recovery key stored in Microsoft Entra ID.

    .DESCRIPTION
    Matches the encrypted managed Windows devices in Intune (isEncrypted, azureADDeviceId) with the BitLocker recovery
    key metadata in Microsoft Entra ID (informationProtection/bitlocker/recoveryKeys, deviceId). An encrypted device
    without an escrowed key cannot be recovered if the user is locked out. Only the metadata is read, never a key.
    Reading recovery key metadata needs the BitLockerKey.ReadBasic.All permission and a role that may read them.
    #>
    [MaesterTest(
        Id           = 'MP.RESOURCIVE.1009',
        Title        = 'Every encrypted Windows device has its BitLocker recovery key stored in Entra ID.',
        Product      = 'intune',
        RelatedProduct = 'entra',
        Feature      = 'endpoint-security',
        Area         = 'data-protection',
        ResourceType = 'Device',
        Severity     = 'Medium',
        UserImpact   = 'Low',
        ImplementationCost = 'Medium',
        Mitre        = ('T1486'),
        Control      = ('nist-800-53-r5:SC-12'),
        Service      = 'Graph',
        License      = 'INTUNE_A',
        Permission   = ('Graph:Scope:BitLockerKey.ReadBasic.All', 'Graph:Scope:DeviceManagementManagedDevices.Read.All')
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        # Devices that have not synced with Intune for this many days are left out.
        [ValidateRange(7, 365)]
        [int] $StaleDays = 30
    )

    Assert-ResLicense -Name 'Microsoft Intune Plan 1' -ServicePlan (Get-ResServicePlanName -Product Intune)

    try {
        $staleBefore = (Get-Date).ToUniversalTime().AddDays(-$StaleDays)
        $devices = @(Get-ResWindowsManagedDevice | Where-Object { $_.isEncrypted -eq $true -and $_.azureADDeviceId -and $_.azureADDeviceId -ne '00000000-0000-0000-0000-000000000000' -and -not ($_.lastSyncDateTime -and ([datetime]$_.lastSyncDateTime).ToUniversalTime() -lt $staleBefore) })
        $keys = @(Invoke-MtGraphRequest -RelativeUri 'informationProtection/bitlocker/recoveryKeys' -ApiVersion v1.0 -Select id, deviceId, createdDateTime -ErrorAction Stop)
    } catch {
        Resolve-ResGraphError -ErrorRecord $_ -Feature 'BitLocker recovery key metadata' -Requires 'BitLockerKey.ReadBasic.All and a role that may read recovery keys (for example Security Reader)'
    }

    if ($devices.Count -eq 0) {
        Add-MtTestResultDetail -SkippedBecause NotApplicable
    }

    $withKey = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($key in $keys) { $null = $withKey.Add([string]$key.deviceId) }
    $missing = @($devices | Where-Object { -not $withKey.Contains([string]$_.azureADDeviceId) })

    $summary = "$($devices.Count - $missing.Count) of $($devices.Count) encrypted Windows devices have a recovery key in Entra ID, as of $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm')) UTC. Devices that have not synced for $StaleDays days are not counted."
    if ($missing.Count -eq 0) {
        Add-MtTestResultDetail -Result "Well done. $summary"
        return $true
    }

    $table = "`n`n| Device | User | Last sync |`n| --- | --- | --- |`n" + ((@($missing) | Select-Object -First 50 | ForEach-Object { "| $($_.deviceName) | $($_.userPrincipalName) | $($_.lastSyncDateTime) |" }) -join "`n")
    if ($missing.Count -gt 50) { $table += "`n`nThe first 50 of $($missing.Count) devices are shown." }
    $hybridNote = "`n`nHybrid joined devices may store their recovery key in on-premises Active Directory instead of Entra ID, so a missing key is not always a gap for them."
    Add-MtTestResultDetail -Result "$summary$table$hybridNote"
    return $false
}
