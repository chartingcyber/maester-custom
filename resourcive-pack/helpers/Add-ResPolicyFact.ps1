function Add-ResPolicyFact {
    <#
    .SYNOPSIS
    Adds what the pack knows about a Conditional Access policy to the report's Affected objects page.

    .DESCRIPTION
    Adds facts with Add-MtAffectedObjectFact for one Conditional Access policy: its state (enforced, report-only or
    off), who it targets, what it requires and when it was last changed, plus the calling check's own facts. Facts only
    describe a policy that a check names with Add-MtTestResultDetail -GraphObjects. The call does nothing in a run that
    does not collect affected objects, and nothing for a policy without an ID.

    .EXAMPLE
    Add-ResPolicyFact -Policy $policy -Fact @{ Name = 'Privileged users excluded'; Value = '3'; Tone = 'Risk'; Key = 'resourcive.privilegedExcluded'; Raw = 3 }
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        # A policy from Get-MtConditionalAccessPolicy.
        [Parameter(Mandatory)]
        [pscustomobject] $Policy,

        # Facts the calling check adds for itself.
        [object[]] $Fact = @(),

        [datetime] $AsOf = [datetime]::UtcNow
    )

    if (-not $Policy.id) { return }
    $state = switch ([string]$Policy.state) {
        'enabled' { 'Enforced' }
        'enabledForReportingButNotEnforced' { 'Report-only' }
        'disabled' { 'Off' }
        default { [string]$Policy.state }
    }
    $users = $Policy.conditions.users
    $includeUsers = @($users.includeUsers)
    $target = if ($includeUsers -contains 'All') { 'All users' }
    else {
        $parts = @()
        if ($includeUsers.Count -gt 0 -and $includeUsers -notcontains 'None') { $parts += "$($includeUsers.Count) user(s)" }
        if (@($users.includeGroups).Count -gt 0) { $parts += "$(@($users.includeGroups).Count) group(s)" }
        if (@($users.includeRoles).Count -gt 0) { $parts += "$(@($users.includeRoles).Count) role(s)" }
        if ($parts.Count -gt 0) { $parts -join ', ' } else { 'Nobody listed' }
    }
    $controls = @()
    if (@($Policy.grantControls.builtInControls) -contains 'block') { $controls = @('Block access') }
    else { $controls = @($Policy.grantControls.builtInControls | Where-Object { $_ }) }
    if ($Policy.grantControls.authenticationStrength.displayName) { $controls += "Authentication strength: $($Policy.grantControls.authenticationStrength.displayName)" }

    $facts = [System.Collections.Generic.List[object]]::new()
    $facts.Add(@{ Name = 'State'; Value = $state; Tone = $(if ($state -eq 'Enforced') { 'Good' } elseif ($state -eq 'Report-only') { 'Warning' } else { 'Info' }); Key = 'resourcive.caState'; Raw = $state })
    $facts.Add(@{ Name = 'Targets'; Value = $target; Tone = 'Info' })
    $facts.Add(@{ Name = 'Requires'; Value = $(if ($controls.Count -gt 0) { $controls -join ', ' } else { 'No grant control' }); Tone = 'Info' })
    if (@($users.excludeUsers).Count + @($users.excludeGroups).Count + @($users.excludeRoles).Count -gt 0) {
        $facts.Add(@{
                Name  = 'Exclusions'
                Value = "$(@($users.excludeUsers).Count) user(s), $(@($users.excludeGroups).Count) group(s), $(@($users.excludeRoles).Count) role(s)"
                Tone  = 'Info'
                Key   = 'resourcive.caExclusionCount'
                Raw   = @($users.excludeUsers).Count + @($users.excludeGroups).Count + @($users.excludeRoles).Count
            })
    }
    if ($Policy.modifiedDateTime) { $facts.Add(@{ Name = 'Last modified'; Value = ([datetime]$Policy.modifiedDateTime).ToUniversalTime().ToString('yyyy-MM-dd'); Tone = 'Info' }) }
    foreach ($item in @($Fact)) { if ($item) { $facts.Add($item) } }
    Add-MtAffectedObjectFact -Type ConditionalAccessPolicy -Id ([string]$Policy.id) -Source 'Resourcive M365 Assessment' -AsOf $AsOf -Fact $facts.ToArray()
}
