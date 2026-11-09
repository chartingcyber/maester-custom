function Test-ResUntrustedScriptsBlocked {
    <#
    .SYNOPSIS
    Checks that untrusted scripts are blocked on all Windows devices, by attack surface reduction script rules or by an enforcing App Control for Business policy.

    .DESCRIPTION
    Passes when either
    - every attack surface reduction script rule (obfuscated scripts, JavaScript or VBScript launching downloaded
      executable content) is in Block mode in a policy that reaches all devices or all users; or
    - an App Control for Business policy is enforcing (audit mode off) and reaches all devices or all users.
    A rule in Audit or Warn mode does not count as blocking. A control that reaches only some groups is reported as
    Partial scope and the result is Investigate.

    PowerShell Constrained Language Mode is not assessed: it is set on the device (by App Control, or the
    __PSLockdownPolicy environment variable) and cannot be read from tenant settings.
    #>
    [MaesterTest(
        Id           = 'MP.RESOURCIVE.1004',
        Title        = 'Untrusted scripts are blocked on all Windows devices.',
        Product      = 'intune',
        RelatedProduct = 'defender',
        Feature      = 'endpoint-security',
        Area         = 'devices',
        ResourceType = 'Tenant',
        Severity     = 'High',
        UserImpact   = 'Medium',
        ImplementationCost = 'Medium',
        Mitre        = ('T1059', 'T1204.002'),
        Control      = ('nist-800-53-r5:CM-7', 'nist-800-53-r5:SI-3'),
        Service      = 'Graph',
        License      = ('INTUNE_A&MDE_SMB', 'INTUNE_A&MDE_LITE', 'INTUNE_A&WINDEFATP'),
        Permission   = 'Graph:Scope:DeviceManagementConfiguration.Read.All'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Assert-ResLicense -Name 'Microsoft Intune Plan 1' -ServicePlan (Get-ResServicePlanName -Product Intune)
    Assert-ResLicense -Name 'Microsoft Defender for Business or Defender for Endpoint' -ServicePlan (Get-ResServicePlanName -Product DefenderEndpoint)

    try {
        $policies = @(Get-ResIntuneConfigurationPolicy -DefinitionIdPattern 'attacksurfacereductionrules_|applicationcontrolv2_')
    } catch {
        Resolve-ResGraphError -ErrorRecord $_ -Feature 'Intune configuration policies' -Requires 'DeviceManagementConfiguration.Read.All'
    }

    $scriptRules = @(Get-ResAsrRule | Where-Object { $_.Group -eq 'Script' })
    $ruleStatus = foreach ($rule in $scriptRules) {
        $status = Get-ResControlStatus -Evidence @(Get-ResPolicyEvidence -Policy $policies -DefinitionId $rule.DefinitionId -EnforcedPattern '_block$' -AuditPattern '_(audit|warn)$')
        [pscustomobject]@{ Rule = $rule.Name; Status = $status.Status; Detail = $status.Detail }
    }

    # App Control for Business: enforcing when the audit mode child setting is not enabled.
    $appControl = foreach ($policy in ($policies | Where-Object { $_.TemplateFamily -eq 'endpointSecurityApplicationControl' -or ($_.Settings | Where-Object { $_.DefinitionId -like 'device_vendor_msft_policy_config_applicationcontrolv2_*' }) })) {
        $audit = $policy.Settings | Where-Object { $_.DefinitionId -eq 'device_vendor_msft_policy_config_applicationcontrolv2_auditmode' } | Select-Object -First 1
        $isAudit = $audit -and ([string]$audit.Value) -like '*_enabled'
        [pscustomobject]@{
            Policy     = $policy.Name
            Mode       = if ($isAudit) { 'Audit' } else { 'Enforced' }
            Assignment = $policy.Assignment
        }
    }
    $appControlStatus = Get-ResControlStatus -Evidence @($appControl)

    $rulesEnforced = @($ruleStatus | Where-Object { $_.Status -ne 'Enforced' }).Count -eq 0
    $rulesPartial = @($ruleStatus | Where-Object { $_.Status -eq 'Partial scope' }).Count -gt 0 -and @($ruleStatus | Where-Object { $_.Status -notin @('Enforced', 'Partial scope') }).Count -eq 0

    $table = "| Control | Status |`n| --- | --- |`n"
    foreach ($row in $ruleStatus) { $table += "| ASR rule: $($row.Rule) | $($row.Status) |`n" }
    $table += "| App Control for Business | $($appControlStatus.Status) |`n"
    $notes = "`n`nNot assessed: PowerShell Constrained Language Mode. It is set on the device and cannot be read from tenant settings."

    if ($rulesEnforced -or $appControlStatus.Status -eq 'Enforced') {
        $by = if ($appControlStatus.Status -eq 'Enforced' -and $rulesEnforced) { 'ASR script rules and App Control for Business' } elseif ($appControlStatus.Status -eq 'Enforced') { 'App Control for Business' } else { 'ASR script rules' }
        Add-MtTestResultDetail -Result "Well done. Untrusted scripts are blocked for all devices by $by.`n`n$table$notes"
        return $true
    }

    $text = "Untrusted scripts are not blocked on all Windows devices. Either put the ASR script rules in Block mode for all devices, or enforce an App Control for Business policy for all devices.`n`n$table$notes"
    if ($rulesPartial -or $appControlStatus.Status -eq 'Partial scope') {
        Add-MtTestResultDetail -Result $text -Investigate
    } else {
        Add-MtTestResultDetail -Result $text
    }
    return $false
}
