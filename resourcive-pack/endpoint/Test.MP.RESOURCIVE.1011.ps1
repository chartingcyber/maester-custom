function Test-ResCaRequiresCompliantDevice {
    <#
    .SYNOPSIS
    Checks that an enabled Conditional Access policy requires a compliant device for all users and all resources, and lists who is excluded.

    .DESCRIPTION
    MT.1001 checks that some Conditional Access policy uses device compliance. This check looks at its scope. It
    passes when an enabled policy (not report-only) includes all users and all resources (or Office 365), grants access
    only with a compliant device (or a hybrid joined device), and applies to Windows. The excluded users, groups and
    roles are listed. A policy in report-only mode, or one scoped to a group or to some apps, is reported and the
    result is Investigate.
    #>
    [MaesterTest(
        Id           = 'MP.RESOURCIVE.1011',
        Title        = 'Conditional Access requires a compliant Windows device for all users and apps.',
        Product      = 'entra',
        RelatedProduct = 'intune',
        Feature      = 'conditional-access',
        Area         = 'access-control',
        ResourceType = 'ConditionalAccessPolicy',
        Severity     = 'High',
        UserImpact   = 'High',
        ImplementationCost = 'High',
        Mitre        = ('T1078', 'T1550.004'),
        Control      = ('nist-800-53-r5:AC-19', 'nist-800-53-r5:AC-17'),
        Service      = 'Graph',
        License      = ('AAD_PREMIUM&INTUNE_A'),
        Permission   = 'Graph:Scope:Policy.Read.All'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Assert-ResLicense -Name 'Microsoft Entra ID P1' -ServicePlan (Get-ResServicePlanName -Product EntraP1)
    Assert-ResLicense -Name 'Microsoft Intune Plan 1' -ServicePlan (Get-ResServicePlanName -Product Intune)

    try {
        $policies = @(Get-MtConditionalAccessPolicy)
    } catch {
        Resolve-ResGraphError -ErrorRecord $_ -Feature 'Conditional Access policies' -Requires 'Policy.Read.All'
    }

    $deviceControls = @('compliantDevice', 'domainJoinedDevice')
    $candidates = foreach ($policy in $policies) {
        $controls = @($policy.grantControls.builtInControls | Where-Object { $_ })
        if (-not ($controls | Where-Object { $_ -in $deviceControls })) { continue }
        # With OR, the other control is an alternative; with AND (or one control), the device is required.
        $deviceRequired = ($policy.grantControls.operator -eq 'AND') -or (@($controls).Count -eq 1)
        $allUsers = @($policy.conditions.users.includeUsers) -contains 'All'
        $apps = @($policy.conditions.applications.includeApplications | Where-Object { $_ })
        $allApps = ($apps -contains 'All') -or ($apps -contains 'Office365')
        $platforms = @($policy.conditions.platforms.includePlatforms | Where-Object { $_ })
        $windows = ($platforms.Count -eq 0) -or ($platforms -contains 'all') -or ($platforms -contains 'windows')
        $excluded = @(@($policy.conditions.users.excludeUsers) + @($policy.conditions.users.excludeGroups) + @($policy.conditions.users.excludeRoles) | Where-Object { $_ }).Count
        [pscustomobject]@{
            Name      = [string]$policy.displayName
            State     = [string]$policy.state
            Everyone  = $allUsers -and $allApps -and $windows -and $deviceRequired
            Excluded  = $excluded
        }
    }
    $candidates = @($candidates | Where-Object { $null -ne $_ })

    $enforced = @($candidates | Where-Object { $_.State -eq 'enabled' -and $_.Everyone })
    $reportOnly = @($candidates | Where-Object { $_.State -eq 'enabledForReportingButNotEnforced' -and $_.Everyone })

    $table = ''
    if ($candidates.Count -gt 0) {
        $table = "`n`n| Policy | State | Covers all users, apps and Windows | Excluded users, groups and roles |`n| --- | --- | --- | --- |`n" +
            ((@($candidates) | ForEach-Object { "| $($_.Name) | $($_.State) | $(if ($_.Everyone) { 'Yes' } else { 'No' }) | $($_.Excluded) |" }) -join "`n")
    }

    if ($enforced.Count -gt 0) {
        Add-MtTestResultDetail -Result "Well done. An enabled Conditional Access policy requires a compliant device for all users and apps on Windows.$table"
        return $true
    }
    if ($reportOnly.Count -gt 0 -or $candidates.Count -gt 0) {
        $why = if ($reportOnly.Count -gt 0) { 'The policy that covers everyone is in report-only mode and does not enforce.' } else { 'Policies that require a device are scoped to some users or apps only.' }
        Add-MtTestResultDetail -Result "$why Confirm the scope is intended.$table" -Investigate
        return $false
    }
    Add-MtTestResultDetail -Result 'No Conditional Access policy requires a compliant or hybrid joined device.'
    return $false
}
