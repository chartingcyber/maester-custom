function Test-ResDefenderAntivirusBaseline {
    <#
    .SYNOPSIS
    Checks that the core Microsoft Defender Antivirus protections are turned on by a policy that reaches all Windows devices.

    .DESCRIPTION
    Reads settings catalog policies (endpoint security Antivirus profiles and Settings catalog) and reports, for each
    core protection, whether it is Enforced for all devices or users, Partial scope, Not assigned or Not configured:
    real-time protection, behavior monitoring, cloud-delivered protection, scanning of downloaded files and
    attachments (IOAV), network protection (block mode) and potentially unwanted application protection (block mode).
    Whether the protections are actually on, on each device, is checked by MP.RESOURCIVE.1007.
    #>
    [MaesterTest(
        Id           = 'MP.RESOURCIVE.1006',
        Title        = 'Core Microsoft Defender Antivirus protections are enforced by policy on all Windows devices.',
        Product      = 'defender',
        RelatedProduct = 'intune',
        Feature      = 'endpoint-antivirus',
        Area         = 'devices',
        ResourceType = 'Tenant',
        Severity     = 'High',
        UserImpact   = 'Low',
        ImplementationCost = 'Low',
        Mitre        = ('T1562.001', 'T1204.002'),
        Control      = ('nist-800-53-r5:SI-3'),
        Service      = 'Graph',
        License      = 'INTUNE_A',
        Permission   = 'Graph:Scope:DeviceManagementConfiguration.Read.All'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Assert-ResLicense -Name 'Microsoft Intune Plan 1' -ServicePlan (Get-ResServicePlanName -Product Intune)

    try {
        $policies = @(Get-ResIntuneConfigurationPolicy -DefinitionIdPattern '^device_vendor_msft_policy_config_defender_')
    } catch {
        Resolve-ResGraphError -ErrorRecord $_ -Feature 'Intune configuration policies' -Requires 'DeviceManagementConfiguration.Read.All'
    }

    # Each protection, the setting that turns it on, and the values that count as enforcing and as audit.
    $controls = @(
        @{ Name = 'Real-time protection'; Id = 'device_vendor_msft_policy_config_defender_allowrealtimemonitoring'; On = '_1$'; Audit = $null }
        @{ Name = 'Behavior monitoring'; Id = 'device_vendor_msft_policy_config_defender_allowbehaviormonitoring'; On = '_1$'; Audit = $null }
        @{ Name = 'Cloud-delivered protection'; Id = 'device_vendor_msft_policy_config_defender_allowcloudprotection'; On = '_1$'; Audit = $null }
        @{ Name = 'Scan downloaded files and attachments'; Id = 'device_vendor_msft_policy_config_defender_allowioavprotection'; On = '_1$'; Audit = $null }
        @{ Name = 'Network protection (block mode)'; Id = 'device_vendor_msft_policy_config_defender_enablenetworkprotection'; On = '_1$'; Audit = '_2$' }
        @{ Name = 'Potentially unwanted application protection (block mode)'; Id = 'device_vendor_msft_policy_config_defender_puaprotection'; On = '_1$'; Audit = '_2$' }
    )

    $rows = foreach ($control in $controls) {
        $evidence = @(Get-ResPolicyEvidence -Policy $policies -DefinitionId $control.Id -EnforcedPattern $control.On -AuditPattern $control.Audit)
        $status = Get-ResControlStatus -Evidence $evidence
        [pscustomobject]@{ Control = $control.Name; Status = $status.Status }
    }

    $failing = @($rows | Where-Object { $_.Status -notin @('Enforced', 'Partial scope') })
    $partial = @($rows | Where-Object { $_.Status -eq 'Partial scope' })
    $table = "| Protection | Status |`n| --- | --- |`n" + ((@($rows) | ForEach-Object { "| $($_.Control) | $($_.Status) |" }) -join "`n")

    $caveat = "`n`nOnly Intune settings catalog policies are read. A protection set through a security baseline, a legacy Endpoint Protection profile, Group Policy or the Defender portal shows here as Not configured, so confirm that before treating a gap as real."
    if ($failing.Count -eq 0 -and $partial.Count -eq 0) {
        Add-MtTestResultDetail -Result "Well done. All core Defender Antivirus protections are enforced for all devices.`n`n$table"
        return $true
    }
    if ($failing.Count -eq 0) {
        Add-MtTestResultDetail -Result "Some protections reach only part of the tenant. Confirm the assigned groups cover every Windows device.`n`n$table$caveat" -Investigate
        return $false
    }
    Add-MtTestResultDetail -Result "$($failing.Count) of $($rows.Count) core protections are not enforced by a policy for all devices.`n`n$table$caveat"
    return $false
}
