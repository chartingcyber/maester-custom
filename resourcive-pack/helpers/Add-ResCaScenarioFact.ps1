function Add-ResCaScenarioFact {
    <#
    .SYNOPSIS
    Adds the users and Conditional Access policies behind a failing What If scenario to the Affected objects page.

    .DESCRIPTION
    Called for each scenario that fails or needs review. The persona's user and the policies that exclude the persona
    are added as facts, and returned as objects for Add-MtTestResultDetail -GraphObjects.

    A persona is one real user standing for a class of users that the policies treat alike, so the user's facts say how
    many users the persona represents, how many scenarios have failed for it and a few examples; they never say the
    user alone has the gap. The policies that exclude the persona's class get a fact with the number of failing
    scenarios in which they excluded it, so the policy at the top of the Affected objects page is the first one to look
    at. Facts of one source with the same key replace each other, so the running counts are kept in the run's shared
    cache and each call writes the latest. With Redact set the user is not named at all.

    Returns the objects to name (users and policies) as made by New-ResGraphObject.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        # The scenario from New-ResCaScenario.
        [Parameter(Mandatory)]
        $Scenario,

        # The verdict from Test-ResCaExpectation: Status and Reason.
        [Parameter(Mandatory)]
        $Verdict,

        # The tenant's policies, to look the excluding policies up by name.
        [AllowEmptyCollection()]
        [object[]] $Policy = @(),

        # The run's shared hashtable, which holds the running counts between scenarios.
        [Parameter(Mandatory)]
        [hashtable] $Cache,

        # Do not name the user.
        [switch] $Redact
    )

    $persona = $Scenario.Persona
    $target = if ($Scenario.UserAction) { "user action $($Scenario.UserAction)" } else { $Scenario.App.Name }
    $example = "$target from $($Scenario.LocationKey) with $($Scenario.ClientAppType) on $($Scenario.DevicePlatform): $($Verdict.Reason)"
    $excludingNames = @($persona.ClassPolicies | Where-Object { $_ -match '\(Excluded\)$' } | ForEach-Object { $_ -replace ' \(Excluded\)$', '' })
    $excludingPolicies = @($Policy | Where-Object { $_.displayName -in $excludingNames -and $_.id })
    $asOf = [datetime]::UtcNow

    $failCount = 0
    $reviewCount = 0
    $examples = @()
    $policyCounts = @{}
    [System.Threading.Monitor]::Enter($Cache.SyncRoot)
    try {
        $key = "resCaGap:$($persona.Key)"
        if (-not $Cache.ContainsKey($key)) { $Cache[$key] = @{ Fail = 0; Review = 0; Examples = [System.Collections.Generic.List[string]]::new() } }
        $entry = $Cache[$key]
        if ($Verdict.Status -eq 'Fail') { $entry.Fail++ } else { $entry.Review++ }
        if ($entry.Examples.Count -lt 5) { $entry.Examples.Add($example) }
        $failCount = $entry.Fail
        $reviewCount = $entry.Review
        $examples = @($entry.Examples)
        foreach ($p in $excludingPolicies) {
            $policyKey = "resCaExcl:$($p.id)"
            $Cache[$policyKey] = 1 + [int]$Cache[$policyKey]
            $policyCounts[$p.id] = $Cache[$policyKey]
        }
    } finally {
        [System.Threading.Monitor]::Exit($Cache.SyncRoot)
    }

    $objects = [System.Collections.Generic.List[object]]::new()
    if (-not $Redact -and $persona.UserId) {
        $classSize = if ($persona.ClassSize) { [int]$persona.ClassSize } else { 1 }
        $personaFacts = [System.Collections.Generic.List[object]]::new()
        $personaFacts.Add(@{ Name = 'Stands for'; Value = $(if ($classSize -gt 1) { "$classSize users that the policies treat alike" } else { 'Itself only' }); Tone = 'Info'; Key = 'resourcive.personaClassSize'; Raw = $classSize })
        if ($failCount -gt 0) {
            $personaFacts.Add(@{ Name = 'Failing sign-in scenarios'; Value = "$failCount so far for this persona$(if ($classSize -gt 1) { ' (a gap here applies to the whole class)' })"; Tone = 'Risk'; Key = 'resourcive.caFailingScenarios'; Raw = $failCount })
        }
        if ($reviewCount -gt 0) {
            $personaFacts.Add(@{ Name = 'Sign-in scenarios to review'; Value = "$reviewCount so far for this persona (informational or not assessed, not a failure)"; Tone = 'Warning'; Key = 'resourcive.caReviewScenarios'; Raw = $reviewCount })
        }
        $personaFacts.Add(@{ Name = 'Examples'; Value = ($examples -join ' | '); Tone = 'Info' })
        Add-MtAffectedObjectFact -Type User -Id ([string]$persona.UserId) -Source 'Resourcive M365 Assessment' -AsOf $asOf -Fact $personaFacts.ToArray()
        $objects.Add((New-ResGraphObject -Type User -Id ([string]$persona.UserId) -DisplayName ([string]$persona.DisplayName) -UserPrincipalName ([string]$persona.UserPrincipalName)))
    }
    foreach ($p in $excludingPolicies) {
        Add-ResPolicyFact -Policy $p -AsOf $asOf -Fact @(
            @{ Name = 'Excludes users in failing scenarios'; Value = "$($policyCounts[$p.id]) failing sign-in scenario(s) so far where the user is excluded from this policy"; Tone = 'Risk'; Key = 'resourcive.caExcludedFailures'; Raw = [int]$policyCounts[$p.id] }
        )
        $objects.Add((New-ResGraphObject -Type ConditionalAccessPolicy -Id ([string]$p.id) -DisplayName ([string]$p.displayName)))
    }
    $objects.ToArray()
}
