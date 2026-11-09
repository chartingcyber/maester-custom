function Test-ResWindowsCompliancePolicyCoverage {
    <#
    .SYNOPSIS
    Checks that Windows compliance policies reach all devices and, together, require BitLocker, Defender, real-time protection and the firewall.

    .DESCRIPTION
    Reads the Windows 10 and later compliance policies with their assignments and actions for non-compliance. The
    check passes when the policies that reach all devices or all users (no exclusions) together require every setting
    in RequiredSettings, and at least one of them blocks a non-compliant device within MaximumGraceDays. A policy that
    reaches only groups is reported and the result is Investigate when it would otherwise complete the requirement.
    MT.1054 checks that devices with no compliance policy are marked not compliant; this check checks what the
    policies require.
    #>
    [MaesterTest(
        Id           = 'MP.RESOURCIVE.1010',
        Title        = 'Windows compliance policies reach all devices and require encryption, antivirus and the firewall.',
        Product      = 'intune',
        Feature      = 'device-compliance',
        Area         = 'devices',
        ResourceType = 'Tenant',
        Severity     = 'High',
        UserImpact   = 'Medium',
        ImplementationCost = 'Medium',
        Mitre        = ('T1078', 'T1562.001'),
        Control      = ('nist-800-53-r5:CM-6', 'nist-800-53-r5:AC-19'),
        Service      = 'Graph',
        License      = 'INTUNE_A',
        Permission   = 'Graph:Scope:DeviceManagementConfiguration.Read.All'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        # The compliance settings that the policies together must require.
        [ValidateSet('bitLockerEnabled', 'secureBootEnabled', 'codeIntegrityEnabled', 'defenderEnabled', 'rtpEnabled', 'antivirusRequired', 'antiSpywareRequired', 'activeFirewallRequired', 'tpmRequired', 'passwordRequired')]
        [string[]] $RequiredSettings = @('bitLockerEnabled', 'defenderEnabled', 'rtpEnabled', 'activeFirewallRequired'),

        # The most days a non-compliant device may stay usable before the block action.
        [ValidateRange(0, 90)]
        [int] $MaximumGraceDays = 7
    )

    Assert-ResLicense -Name 'Microsoft Intune Plan 1' -ServicePlan (Get-ResServicePlanName -Product Intune)

    try {
        # One expand per request: Invoke-MtGraphRequest cuts a query string with a nested $expand at its second equals sign.
        $all = @(Invoke-MtGraphRequest -RelativeUri 'deviceManagement/deviceCompliancePolicies?$expand=assignments' -ApiVersion beta -ErrorAction Stop)
        $actionRules = @{}
        foreach ($windowsPolicy in @($all | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.windows10CompliancePolicy' })) {
            # scheduledActionsForRule is not addressable as a sub-path (400); expand it on the policy. The query goes in -QueryParameters so the nested expand is not split at its equals sign.
            $withActions = Invoke-MtGraphRequest -RelativeUri "deviceManagement/deviceCompliancePolicies/$($windowsPolicy.id)" -QueryParameters @{ '$expand' = 'scheduledActionsForRule($expand=scheduledActionConfigurations)' } -ApiVersion beta -ErrorAction Stop
            $actionRules[[string]$windowsPolicy.id] = @($withActions.scheduledActionsForRule)
        }
    } catch {
        Resolve-ResGraphError -ErrorRecord $_ -Feature 'Intune compliance policies' -Requires 'DeviceManagementConfiguration.Read.All'
    }

    $policies = @($all | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.windows10CompliancePolicy' } | ForEach-Object {
            $blockDays = $null
            foreach ($rule in @($actionRules[[string]$_.id])) {
                foreach ($action in @($rule.scheduledActionConfigurations)) {
                    if ($action.actionType -eq 'block') {
                        $days = [math]::Floor([double]$action.gracePeriodHours / 24)
                        if ($null -eq $blockDays -or $days -lt $blockDays) { $blockDays = $days }
                    }
                }
            }
            [pscustomobject]@{
                Name       = [string]$_.displayName
                Item       = $_
                Assignment = ConvertTo-ResAssignmentSummary -Assignment @($_.assignments)
                BlockDays  = $blockDays
            }
        })

    if ($policies.Count -eq 0) {
        Add-MtTestResultDetail -Result "No Windows 10 and later compliance policy exists. Create one under **Devices** > **Compliance** and assign it to all devices."
        return $false
    }

    function Get-CoveredSetting {
        param($Set)
        $covered = @{}
        foreach ($setting in $RequiredSettings) {
            $covered[$setting] = [bool](@($Set) | Where-Object { $_.Item.$setting -eq $true })
        }
        $covered
    }
    $everyone = @($policies | Where-Object { $_.Assignment.Scope -in @('AllDevices', 'AllUsers') -and -not $_.Assignment.HasExclusions })
    $partialSet = @($policies | Where-Object { $_.Assignment.Scope -ne 'None' })
    $coveredEveryone = Get-CoveredSetting -Set $everyone
    $coveredPartial = Get-CoveredSetting -Set $partialSet

    $missingEveryone = @($RequiredSettings | Where-Object { -not $coveredEveryone[$_] })
    $missingPartial = @($RequiredSettings | Where-Object { -not $coveredPartial[$_] })
    $blockOk = [bool](@($everyone | Where-Object { $null -ne $_.BlockDays -and $_.BlockDays -le $MaximumGraceDays }))

    $table = "| Policy | Assigned to | Block action after (days) |`n| --- | --- | --- |`n"
    foreach ($policy in $policies) { $table += "| $($policy.Name) | $($policy.Assignment.Text) | $(if ($null -eq $policy.BlockDays) { 'none' } else { $policy.BlockDays }) |`n" }
    $required = "Required settings: $($RequiredSettings -join ', '). Required block action: within $MaximumGraceDays day(s)."

    if ($missingEveryone.Count -eq 0 -and $blockOk) {
        Add-MtTestResultDetail -Result "Well done. Compliance policies that reach all devices require every listed setting and block non-compliant devices.`n`n$required`n`n$table"
        return $true
    }

    $gaps = @()
    if ($missingEveryone.Count -gt 0) { $gaps += "Not required by any policy that reaches all devices: $($missingEveryone -join ', ')." }
    if (-not $blockOk) { $gaps += "No policy that reaches all devices blocks a non-compliant device within $MaximumGraceDays day(s)." }
    $text = "$($gaps -join ' ')`n`n$required`n`n$table"
    if ($missingPartial.Count -eq 0 -and $everyone.Count -eq 0 -and $partialSet.Count -gt 0) {
        Add-MtTestResultDetail -Result "The requirements are met only by policies assigned to groups. Confirm the groups cover every Windows device.`n`n$text" -Investigate
    } else {
        Add-MtTestResultDetail -Result $text
    }
    return $false
}
