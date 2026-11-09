function Test-ResUsbStorageBlocked {
    <#
    .SYNOPSIS
    Checks that USB and other removable storage is blocked by an enforcing policy that reaches all Windows devices.

    .DESCRIPTION
    Removable storage can be blocked in several places in Intune. This reads all of them and reports the status of the
    control as Enforced, Partial scope, Audit-only, Not assigned or Not configured:
    - the Storage CSP setting RemovableDiskDenyWriteAccess (settings catalog, Device restrictions template, custom OMA-URI);
    - Administrative Templates "Removable Disks: Deny write / read / execute access" and "All Removable Storage classes: Deny all access";
    - Defender for Endpoint device control default enforcement set to Deny (settings catalog or custom OMA-URI);
    - the device restrictions property storageBlockRemovableStorage.
    The attack surface reduction rule "Block untrusted and unsigned processes that run from USB" is reported as a
    related control but does not count as blocking storage. Device control rules (Intune Device Control profile)
    cannot be evaluated reliably from the Graph payload; their presence is reported and the result is Investigate
    when nothing else enforces.
    #>
    [MaesterTest(
        Id           = 'MP.RESOURCIVE.1003',
        Title        = 'USB and removable storage is blocked on all Windows devices.',
        Product      = 'intune',
        RelatedProduct = 'defender',
        Feature      = 'endpoint-security',
        Area         = 'devices',
        ResourceType = 'Tenant',
        Severity     = 'Medium',
        UserImpact   = 'Medium',
        ImplementationCost = 'Medium',
        Mitre        = ('T1091', 'T1052.001', 'T1200'),
        Control      = ('nist-800-53-r5:MP-7', 'nist-800-53-r5:CM-7'),
        Service      = 'Graph',
        License      = 'INTUNE_A',
        Permission   = 'Graph:Scope:DeviceManagementConfiguration.Read.All'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        # Count only policies that also block reading from removable storage, not just writing to it.
        [switch] $RequireReadBlock
    )

    Assert-ResLicense -Name 'Microsoft Intune Plan 1' -ServicePlan (Get-ResServicePlanName -Product Intune)

    try {
        $catalogPattern = 'removablediskdeny|admx_removablestorage|defaultenforcement|devicecontrol|securedevicesconfiguration|blockuntrustedunsignedprocessesthatrunfromusb'
        $catalog = @(Get-ResIntuneConfigurationPolicy -DefinitionIdPattern $catalogPattern)
        $legacy = @(Get-ResIntuneLegacyProfile)
    } catch {
        Resolve-ResGraphError -ErrorRecord $_ -Feature 'Intune device configuration' -Requires 'DeviceManagementConfiguration.Read.All'
    }

    # Level: Write (blocks writing), Read (also blocks reading or all access), Default deny (device control default enforcement).
    $evidence = [System.Collections.Generic.List[pscustomobject]]::new()
    function Add-UsbEvidence {
        param($Policy, $Source, $Level, $Assignment)
        $evidence.Add([pscustomobject]@{ Policy = $Policy; Source = $Source; Level = $Level; Mode = 'Enforced'; Assignment = $Assignment })
    }

    foreach ($policy in $catalog) {
        foreach ($setting in $policy.Settings) {
            $enabled = ([string]$setting.Value) -match '_1$'
            switch -Regex ($setting.DefinitionId) {
                '^device_vendor_msft_policy_config_storage_removablediskdenywriteaccess$' { if ($enabled) { Add-UsbEvidence $policy.Name 'Storage CSP (settings catalog)' 'Write' $policy.Assignment } }
                'admx_removablestorage_removabledisks_denywrite' { if ($enabled) { Add-UsbEvidence $policy.Name 'Administrative Template (settings catalog)' 'Write' $policy.Assignment } }
                'admx_removablestorage_removabledisks_denyread' { if ($enabled) { Add-UsbEvidence $policy.Name 'Administrative Template (settings catalog)' 'Read' $policy.Assignment } }
                'admx_removablestorage_removablestorageclasses_denyall' { if ($enabled) { Add-UsbEvidence $policy.Name 'Administrative Template (settings catalog)' 'Read' $policy.Assignment } }
                '^device_vendor_msft_defender_configuration_defaultenforcement$' { if (([string]$setting.Value) -match '_2$') { Add-UsbEvidence $policy.Name 'Device control default enforcement: Deny' 'Read' $policy.Assignment } }
            }
        }
    }

    foreach ($profile in $legacy) {
        if ($profile.Kind -eq 'DeviceRestrictions' -and $profile.Properties.storageBlockRemovableStorage -eq $true) {
            Add-UsbEvidence $profile.Name 'Device restrictions: block removable storage' 'Read' $profile.Assignment
        }
        foreach ($oma in $profile.OmaSettings) {
            if ($oma.OmaUri -match 'Storage/RemovableDiskDenyWriteAccess$' -and $oma.Value -eq '1') { Add-UsbEvidence $profile.Name 'Custom OMA-URI: RemovableDiskDenyWriteAccess' 'Write' $profile.Assignment }
            if ($oma.OmaUri -match 'Defender/Configuration/DefaultEnforcement$' -and $oma.Value -eq '2') { Add-UsbEvidence $profile.Name 'Custom OMA-URI: device control default Deny' 'Read' $profile.Assignment }
        }
        foreach ($definition in $profile.AdmxDefinitions) {
            if (-not $definition.Enabled -or $definition.CategoryPath -notmatch 'Removable Storage Access') { continue }
            if ($definition.DisplayName -match 'Deny write access') { Add-UsbEvidence $profile.Name "Administrative Template: $($definition.DisplayName)" 'Write' $profile.Assignment }
            elseif ($definition.DisplayName -match 'Deny read access|Deny all access') { Add-UsbEvidence $profile.Name "Administrative Template: $($definition.DisplayName)" 'Read' $profile.Assignment }
        }
    }

    $counted = @($evidence | Where-Object { -not $RequireReadBlock -or $_.Level -eq 'Read' })
    $status = Get-ResControlStatus -Evidence $counted

    # Related controls that are reported but do not count.
    $asrKey = 'device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockuntrustedunsignedprocessesthatrunfromusb'
    $asrEvidence = @(Get-ResPolicyEvidence -Policy $catalog -DefinitionId $asrKey -EnforcedPattern '_block$' -AuditPattern '_(audit|warn)$')
    $asrStatus = Get-ResControlStatus -Evidence $asrEvidence
    $deviceControlPolicies = @($catalog | Where-Object { $_.Settings | Where-Object { $_.DefinitionId -match 'devicecontrol' } })

    $table = ''
    if ($evidence.Count -gt 0) {
        $table = "| Policy | Mechanism | Blocks | Assigned to |`n| --- | --- | --- | --- |`n"
        foreach ($row in $evidence) { $table += "| $($row.Policy) | $($row.Source) | $(if ($row.Level -eq 'Read') { 'Read and write' } else { 'Write' }) | $($row.Assignment.Text) |`n" }
    }
    $required = if ($RequireReadBlock) { 'read and write access to removable storage is blocked' } else { 'write access to removable storage is blocked' }
    $text = "**Status: $($status.Status).** $($status.Detail)`n`nRequired: an enforcing policy where $required, assigned to all devices or all users without exclusions.`n`n$table"
    $text += "`n**Related control, not counted:** ASR rule *Block untrusted and unsigned processes that run from USB* is $($asrStatus.Status)."
    if ($deviceControlPolicies.Count -gt 0) {
        $text += "`n`n**Device control rules found** in: $((@($deviceControlPolicies | ForEach-Object { "$($_.Name) ($($_.Assignment.Text))" })) -join '; '). Rule entries are not evaluated here; review that they deny removable storage."
    }

    switch ($status.Status) {
        'Enforced' {
            Add-MtTestResultDetail -Result "Well done. Removable storage is blocked for all Windows devices.`n`n$text"
            return $true
        }
        'Partial scope' {
            Add-MtTestResultDetail -Result $text -Investigate
            return $false
        }
        default {
            if ($deviceControlPolicies.Count -gt 0) {
                Add-MtTestResultDetail -Result $text -Investigate
            } else {
                Add-MtTestResultDetail -Result $text
            }
            return $false
        }
    }
}
