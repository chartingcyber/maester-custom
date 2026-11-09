function Test-ResBitLockerEnforcedAndEncrypted {
    <#
    .SYNOPSIS
    Checks that a BitLocker policy reaches all Windows devices and that every managed Windows device reports that it is encrypted.

    .DESCRIPTION
    Two views of the same control. The policy view reads settings catalog policies that require device encryption
    (disk encryption profiles) and reports whether one reaches all devices. The device view reads each managed
    Windows device's isEncrypted flag. The check passes when the policy is Enforced for everyone and the share of
    devices reporting encryption is at least MinimumEncryptedPercent. MT.1123 checks the strength of the BitLocker
    settings (full disk encryption type); this check checks coverage and the real device state.
    #>
    [MaesterTest(
        Id           = 'MP.RESOURCIVE.1008',
        Title        = 'BitLocker is required for all Windows devices and the devices are encrypted.',
        Product      = 'intune',
        Feature      = 'endpoint-security',
        Area         = 'data-protection',
        ResourceType = 'Device',
        Severity     = 'High',
        UserImpact   = 'Low',
        ImplementationCost = 'Medium',
        Mitre        = ('T1005', 'T1078'),
        Control      = ('nist-800-53-r5:SC-28', 'nist-800-53-r5:SC-28(1)'),
        Service      = 'Graph',
        License      = 'INTUNE_A',
        Permission   = ('Graph:Scope:DeviceManagementConfiguration.Read.All', 'Graph:Scope:DeviceManagementManagedDevices.Read.All')
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        # The percentage of managed Windows devices that must report that they are encrypted.
        [ValidateRange(1, 100)]
        [int] $MinimumEncryptedPercent = 100,

        # Devices that have not synced with Intune for this many days are listed separately and left out of the percentage.
        [ValidateRange(7, 365)]
        [int] $StaleDays = 30
    )

    Assert-ResLicense -Name 'Microsoft Intune Plan 1' -ServicePlan (Get-ResServicePlanName -Product Intune)

    try {
        $policies = @(Get-ResIntuneConfigurationPolicy -DefinitionIdPattern '^device_vendor_msft_bitlocker_requiredeviceencryption')
        $devices = @(Get-ResWindowsManagedDevice)
    } catch {
        Resolve-ResGraphError -ErrorRecord $_ -Feature 'Intune BitLocker policies and managed devices' -Requires 'DeviceManagementConfiguration.Read.All, DeviceManagementManagedDevices.Read.All'
    }

    $policyStatus = Get-ResControlStatus -Evidence @(Get-ResPolicyEvidence -Policy $policies -DefinitionId 'device_vendor_msft_bitlocker_requiredeviceencryption' -EnforcedPattern '_1$')

    $staleBefore = (Get-Date).ToUniversalTime().AddDays(-$StaleDays)
    $stale = @($devices | Where-Object { $_.lastSyncDateTime -and ([datetime]$_.lastSyncDateTime).ToUniversalTime() -lt $staleBefore })
    $devices = @($devices | Where-Object { -not ($_.lastSyncDateTime -and ([datetime]$_.lastSyncDateTime).ToUniversalTime() -lt $staleBefore) })

    $encrypted = @($devices | Where-Object { $_.isEncrypted -eq $true })
    $notEncrypted = @($devices | Where-Object { $_.isEncrypted -ne $true })
    $percent = if ($devices.Count -gt 0) { [math]::Round(100 * $encrypted.Count / $devices.Count, 1) } else { 100 }

    $text = "**Policy: $($policyStatus.Status).** $($policyStatus.Detail)`n`n**Devices:** $($encrypted.Count) of $($devices.Count) managed Windows devices report that they are encrypted ($percent%), as of $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm')) UTC. Required: $MinimumEncryptedPercent%.$(if ($stale.Count -gt 0) { " $($stale.Count) device(s) have not synced for $StaleDays days and are not counted; retire them in Intune or bring them back online." })"
    if ($notEncrypted.Count -gt 0) {
        $text += "`n`n| Device | User | Last sync |`n| --- | --- | --- |`n" + ((@($notEncrypted) | Select-Object -First 50 | ForEach-Object { "| $($_.deviceName) | $($_.userPrincipalName) | $($_.lastSyncDateTime) |" }) -join "`n")
        if ($notEncrypted.Count -gt 50) { $text += "`n`nThe first 50 of $($notEncrypted.Count) devices are shown." }
    }

    $devicesOk = $percent -ge $MinimumEncryptedPercent
    if ($policyStatus.Status -eq 'Enforced' -and $devicesOk) {
        Add-MtTestResultDetail -Result "Well done. BitLocker is required for all devices and the devices report that they are encrypted.`n`n$text"
        return $true
    }
    if ($policyStatus.Status -eq 'Partial scope' -and $devicesOk) {
        Add-MtTestResultDetail -Result $text -Investigate
        return $false
    }
    Add-MtTestResultDetail -Result $text
    return $false
}
