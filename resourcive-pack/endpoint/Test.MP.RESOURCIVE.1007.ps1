function Test-ResDefenderDeviceProtectionState {
    <#
    .SYNOPSIS
    Checks the real Defender Antivirus state of every Windows device that Intune manages: real-time protection, tamper protection and up-to-date signatures.

    .DESCRIPTION
    A policy can say a protection is on while a device reports it off. Intune records the Windows protection state of
    each managed device (windowsProtectionState). This check reads it and fails when more than AllowedFailingPercent
    percent of the devices report real-time protection off, tamper protection off, or signatures out of date.
    Devices that have not reported a protection state are listed as not assessed, not as passing.

    Tamper protection is a Defender for Endpoint capability, so a device without it is expected to report it off.
    #>
    [MaesterTest(
        Id           = 'MP.RESOURCIVE.1007',
        Title        = 'Windows devices report real-time protection, tamper protection and current signatures.',
        Product      = 'defender',
        RelatedProduct = 'intune',
        Feature      = 'endpoint-antivirus',
        Area         = 'devices',
        ResourceType = 'Device',
        Severity     = 'High',
        UserImpact   = 'Low',
        ImplementationCost = 'Medium',
        Mitre        = ('T1562.001'),
        Control      = ('nist-800-53-r5:SI-3', 'nist-800-53-r5:SI-2'),
        Service      = 'Graph',
        License      = 'INTUNE_A',
        Permission   = 'Graph:Scope:DeviceManagementManagedDevices.Read.All'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        # The percentage of devices that may report a problem before the check fails.
        [ValidateRange(0, 100)]
        [int] $AllowedFailingPercent = 0,

        # The most devices to read individually when the bulk read does not include the protection state.
        [ValidateRange(1, 5000)]
        [int] $MaximumDevices = 500
    )

    Assert-ResLicense -Name 'Microsoft Intune Plan 1' -ServicePlan (Get-ResServicePlanName -Product Intune)

    try {
        $devices = @(Invoke-MtGraphRequest -RelativeUri "deviceManagement/managedDevices?`$filter=operatingSystem eq 'Windows'&`$select=id,deviceName,userPrincipalName,lastSyncDateTime&`$expand=windowsProtectionState" -ApiVersion beta -ErrorAction Stop)
        if ($devices.Count -gt 0 -and -not ($devices | Where-Object { $_.windowsProtectionState })) {
            # The bulk expand returned no protection state at all; read it device by device.
            $devices = foreach ($device in ($devices | Select-Object -First $MaximumDevices)) {
                $state = Invoke-MtGraphRequest -RelativeUri "deviceManagement/managedDevices/$($device.id)/windowsProtectionState" -ApiVersion beta -ErrorAction SilentlyContinue
                $device | Add-Member -NotePropertyName windowsProtectionState -NotePropertyValue $state -Force -PassThru
            }
        }
    } catch {
        Resolve-ResGraphError -ErrorRecord $_ -Feature 'Intune managed devices' -Requires 'DeviceManagementManagedDevices.Read.All'
    }

    if (@($devices).Count -eq 0) {
        Add-MtTestResultDetail -SkippedBecause NotApplicable
    }

    $assessed = @($devices | Where-Object { $_.windowsProtectionState })
    $notAssessed = @($devices | Where-Object { -not $_.windowsProtectionState })

    $failing = foreach ($device in $assessed) {
        $state = $device.windowsProtectionState
        $problems = [System.Collections.Generic.List[string]]::new()
        if ($state.realTimeProtectionEnabled -eq $false) { $problems.Add('real-time protection off') }
        if ($state.tamperProtectionEnabled -eq $false) { $problems.Add('tamper protection off') }
        if ($state.signatureUpdateOverdue -eq $true) { $problems.Add('signatures out of date') }
        if ($state.malwareProtectionEnabled -eq $false) { $problems.Add('anti-malware off') }
        if ($problems.Count -gt 0) {
            [pscustomobject]@{ Device = $device.deviceName; User = $device.userPrincipalName; Problems = ($problems -join ', ') }
        }
    }

    $failingCount = @($failing | Where-Object { $_ }).Count
    $percent = if ($assessed.Count -gt 0) { [math]::Round(100 * $failingCount / $assessed.Count, 1) } else { 0 }
    $summary = "Assessed $($assessed.Count) of $(@($devices).Count) Windows devices as of $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm')) UTC. $failingCount report a problem ($percent%)."
    if ($notAssessed.Count -gt 0) { $summary += " $($notAssessed.Count) device(s) reported no protection state and are not assessed." }

    $table = ''
    if ($failingCount -gt 0) {
        $table = "`n`n| Device | User | Problems |`n| --- | --- | --- |`n" + ((@($failing) | Select-Object -First 50 | ForEach-Object { "| $($_.Device) | $($_.User) | $($_.Problems) |" }) -join "`n")
        if ($failingCount -gt 50) { $table += "`n`nThe first 50 of $failingCount devices are shown." }
    }

    if ($assessed.Count -eq 0) {
        Add-MtTestResultDetail -Result "$summary`n`nNo device reported a protection state, so nothing could be assessed." -Investigate
        return $false
    }
    if ($percent -le $AllowedFailingPercent) {
        Add-MtTestResultDetail -Result "Well done. $summary$table"
        return $true
    }
    Add-MtTestResultDetail -Result "$summary$table"
    return $false
}
