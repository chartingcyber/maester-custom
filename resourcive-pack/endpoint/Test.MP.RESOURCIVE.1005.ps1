function Test-ResAsrRulesBlocking {
    <#
    .SYNOPSIS
    Checks that every attack surface reduction rule is in Block mode for all Windows devices, and lists the exclusions.

    .DESCRIPTION
    MT.1178 checks three Standard Protection rules. This check covers the whole rule set that Intune exposes. For each
    rule it reports Enforced (Block, reaching all devices or users), Partial scope (Block for some groups), Audit-only
    (Audit or Warn), Not assigned, or Not configured. The check fails when a required rule is not Enforced and is
    Investigate when the only gaps are partial scope. Rules can be left out of the requirement with the
    RulesNotRequired parameter, for example when a business application needs an exception. The Windows Server only
    rule and the preview rules are listed but not required. A rule that a policy sets to Off is reported as Disabled.

    Exclusions (the ASR-only per-rule exclusions and the global ASR exclusions) are listed for review.
    #>
    [MaesterTest(
        Id           = 'MP.RESOURCIVE.1005',
        Title        = 'All attack surface reduction rules are in Block mode on all Windows devices.',
        Product      = 'intune',
        RelatedProduct = 'defender',
        Feature      = 'endpoint-security',
        Area         = 'devices',
        ResourceType = 'Tenant',
        Severity     = 'High',
        UserImpact   = 'Medium',
        ImplementationCost = 'High',
        Mitre        = ('T1003.001', 'T1059', 'T1204.002', 'T1546.003'),
        Control      = ('nist-800-53-r5:CM-7', 'nist-800-53-r5:SI-3'),
        Service      = 'Graph',
        License      = ('INTUNE_A&MDE_SMB', 'INTUNE_A&MDE_LITE', 'INTUNE_A&WINDEFATP'),
        Permission   = 'Graph:Scope:DeviceManagementConfiguration.Read.All'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        # Names of rules, as listed in the result, that are not required to be in Block mode.
        [string[]] $RulesNotRequired = @()
    )

    Assert-ResLicense -Name 'Microsoft Intune Plan 1' -ServicePlan (Get-ResServicePlanName -Product Intune)
    Assert-ResLicense -Name 'Microsoft Defender for Business or Defender for Endpoint' -ServicePlan (Get-ResServicePlanName -Product DefenderEndpoint)

    try {
        $policies = @(Get-ResIntuneConfigurationPolicy -DefinitionIdPattern 'attacksurfacereductionrules|asronlyperruleexclusions|attacksurfacereductiononlyexclusions')
    } catch {
        Resolve-ResGraphError -ErrorRecord $_ -Feature 'Intune configuration policies' -Requires 'DeviceManagementConfiguration.Read.All'
    }

    $rows = foreach ($rule in (Get-ResAsrRule)) {
        $status = Get-ResControlStatus -Evidence @(Get-ResPolicyEvidence -Policy $policies -DefinitionId $rule.DefinitionId -EnforcedPattern '_block$' -AuditPattern '_(audit|warn)$')
        # A rule that a policy sets to Off is reported as Disabled, not as Not configured.
        $label = $status.Status
        if ($label -eq 'Not configured') {
            $isOff = @($policies | ForEach-Object { $_.Settings } | Where-Object { $_.DefinitionId -eq $rule.DefinitionId -and [string]$_.Value -match '_off$' }).Count -gt 0
            if ($isOff) { $label = 'Disabled' }
        }
        $note = switch ($rule.Applicability) { 'ServerOnly' { 'No (Windows Server only)' } 'Preview' { 'No (preview rule)' } default { $null } }
        [pscustomobject]@{
            Rule     = $rule.Name
            Status   = $label
            Required = ($rule.Applicability -eq 'Required') -and ($rule.Name -notin $RulesNotRequired)
            Note     = $note
        }
    }

    $required = @($rows | Where-Object { $_.Required })
    $failing = @($required | Where-Object { $_.Status -notin @('Enforced', 'Partial scope') })
    $partial = @($required | Where-Object { $_.Status -eq 'Partial scope' })

    $exclusions = foreach ($policy in $policies) {
        foreach ($setting in $policy.Settings) {
            if ($setting.DefinitionId -match 'exclusions?$|onlyexclusions|asronlyperruleexclusions' -and -not [string]::IsNullOrWhiteSpace($setting.Value)) {
                [pscustomobject]@{ Policy = $policy.Name; Setting = $setting.DefinitionId -replace '^device_vendor_msft_policy_config_defender_', ''; Value = $setting.Value }
            }
        }
    }

    $table = "| Rule | Status | Required |`n| --- | --- | --- |`n"
    foreach ($row in $rows) { $table += "| $($row.Rule) | $($row.Status) | $(if ($row.Required) { 'Yes' } elseif ($row.Note) { $row.Note } else { 'No' }) |`n" }
    $exclusionText = if (@($exclusions | Where-Object { $_ }).Count -gt 0) {
        "`n`n**Exclusions configured** (review that each is still needed):`n`n| Policy | Setting | Value |`n| --- | --- | --- |`n" + ((@($exclusions) | ForEach-Object { "| $($_.Policy) | $($_.Setting) | $($_.Value) |" }) -join "`n")
    } else { "`n`nNo ASR exclusions are configured." }

    $counts = "$(@($required | Where-Object { $_.Status -eq 'Enforced' }).Count) of $($required.Count) required rules are Enforced."
    if ($failing.Count -eq 0 -and $partial.Count -eq 0) {
        Add-MtTestResultDetail -Result "Well done. $counts`n`n$table$exclusionText"
        return $true
    }
    if ($failing.Count -eq 0) {
        Add-MtTestResultDetail -Result "$counts $($partial.Count) rule(s) reach only some groups. Confirm the groups cover every Windows device.`n`n$table$exclusionText" -Investigate
        return $false
    }
    Add-MtTestResultDetail -Result "$counts $($failing.Count) required rule(s) are not blocking for all devices.`n`n$table$exclusionText"
    return $false
}
