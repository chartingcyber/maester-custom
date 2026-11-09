function Format-ResCaResult {
    <#
    .SYNOPSIS
    Builds the markdown result text of one scenario.

    .DESCRIPTION
    Shows the persona, the scenario parameters, the policies that applied (name, state, grant controls), the
    classification, the expectation, the licence notes, and the time the evaluation ran. A pass starts with
    "Well done.". User names are replaced by the persona label when Redact is set.

    Applications are shown by display name: the ID of the scenario's application and the applications that the
    listed policies target are resolved with Resolve-ResCaAppName (cached in Cache; the ID is shown when a name
    cannot be found). The persona row says how many users its class has and which policies include or exclude the
    class. A verdict with a Severity (a de facto block on a legacy client) shows it in the Expectation row.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] $Scenario,
        [Parameter(Mandatory)] $Outcome,
        [Parameter(Mandatory)] $Expectation,
        [Parameter(Mandatory)] $Verdict,
        # Notes from the instance source: licence notes and truncation.
        [string[]] $Note = @(),
        [datetime] $AsOf = [datetime]::UtcNow,
        [switch] $Redact,
        # Keeps resolved application names between rows. Pass the run's shared cache.
        [hashtable] $Cache = @{}
    )

    $persona = $Scenario.Persona
    $who = if ($Redact) { $persona.Label } else { '{0} ({1})' -f $persona.UserPrincipalName, $persona.Label }
    $policyApps = @(@($Outcome.Enforced) + @($Outcome.ReportOnly) | Where-Object { $_ } |
            ForEach-Object { @($_.conditions.applications.includeApplications) + @($_.conditions.applications.excludeApplications) } | Where-Object { $_ })
    $appIds = @(@($Scenario.App.Id) + $policyApps | Where-Object { $_ } | Select-Object -Unique)
    $appNames = Resolve-ResCaAppName -AppId $appIds -Cache $Cache
    $appName = if ($Scenario.App -and $appNames.ContainsKey([string]$Scenario.App.Id) -and $appNames[[string]$Scenario.App.Id] -ne [string]$Scenario.App.Id) { $appNames[[string]$Scenario.App.Id] } else { [string]$Scenario.App.Name }
    $appName = $appName -replace '^Application ([0-9a-fA-F-]{36})$', '$1'
    $target = if ($Scenario.UserAction) { "user action $($Scenario.UserAction)" } else { "$appName ($($Scenario.App.Id))" }
    function Get-AppList {
        param($Id)
        $list = foreach ($i in @($Id | Where-Object { $_ })) {
            if ($appNames.ContainsKey([string]$i) -and $appNames[[string]$i] -ne [string]$i) { '{0} ({1})' -f $appNames[[string]$i], $i } else { [string]$i }
        }
        @($list) -join ', '
    }
    function Get-AppText {
        param($Policy)
        $a = $Policy.conditions.applications
        if (-not $a) { return '-' }
        $inc = Get-AppList -Id @($a.includeApplications)
        $exc = Get-AppList -Id @($a.excludeApplications)
        $text = if ($inc) { "includes $inc" } else { '-' }
        if ($exc) { $text += "; excludes $exc" }
        $text
    }
    function Get-ClassText {
        $inc = @($persona.ClassPolicies | Where-Object { $_ -match '\(Included\)$' } | ForEach-Object { $_ -replace ' \(Included\)$', '' })
        $exc = @($persona.ClassPolicies | Where-Object { $_ -match '\(Excluded\)$' } | ForEach-Object { $_ -replace ' \(Excluded\)$', '' })
        if ($persona.Kind -eq 'Privileged' -and -not $persona.ClassPolicies) { return '1 user (a privileged user is tested on their own)' }
        $size = if ($persona.ClassSize) { "$($persona.ClassSize) user$(if ($persona.ClassSize -ne 1) { 's' })" } else { 'unknown size' }
        "$size; included by: $(if ($inc) { $inc -join ', ' } else { 'none' }); excluded by: $(if ($exc) { $exc -join ', ' } else { 'none' })"
    }
    function Get-GrantText {
        param($Policy)
        $g = $Policy.grantControls
        if (-not $g) { return 'session controls only or none' }
        $controls = @($g.builtInControls) + @(if ($g.authenticationStrength) { "authentication strength '$($g.authenticationStrength.displayName)'" })
        '{0} ({1})' -f (($controls | Where-Object { $_ }) -join ', '), $(if ($g.operator) { $g.operator } else { 'AND' })
    }

    $text = [System.Text.StringBuilder]::new()
    $head = switch ($Verdict.Status) {
        'Pass' { 'Well done. ' }
        'Fail' { '' }
        default { '' }
    }
    $null = $text.AppendLine("$head$($Verdict.Reason)")
    $null = $text.AppendLine()
    $null = $text.AppendLine('| Item | Value |')
    $null = $text.AppendLine('| --- | --- |')
    $null = $text.AppendLine("| Persona | $who |")
    $null = $text.AppendLine("| Persona class | $(Get-ClassText) |")
    $null = $text.AppendLine("| Signs in to | $target |")
    $null = $text.AppendLine("| Client app type | $($Scenario.ClientAppType) |")
    $null = $text.AppendLine("| Device platform | $($Scenario.DevicePlatform) |")
    $null = $text.AppendLine("| Location | $($Scenario.Country)$(if ($Scenario.IpAddress) { ", $($Scenario.IpAddress)" }) ($($Scenario.LocationKey)) |")
    $null = $text.AppendLine("| Sign-in risk / user risk | $($Scenario.SignInRiskLevel) / $($Scenario.UserRiskLevel) |")
    $null = $text.AppendLine("| Observed outcome | $($Outcome.Class)$(if ($Outcome.PhishingResistant -and $Outcome.Class -ne 'Block') { ' (phishing-resistant)' } elseif ($Outcome.Class -in @('MFA')) { ' (not phishing-resistant)' }) |")
    $null = $text.AppendLine("| Expectation | $($Expectation.Expect) ($($Expectation.Severity), $($Expectation.Source))$(if ($Verdict.Severity) { "; finding severity $($Verdict.Severity)" }) |")
    $null = $text.AppendLine("| Evaluated | $($AsOf.ToString('u')) |")
    $null = $text.AppendLine()

    $null = $text.AppendLine('**Enforced policies that applied**')
    $null = $text.AppendLine()
    if (@($Outcome.Enforced).Count -eq 0) {
        $null = $text.AppendLine('None. No enforced policy applies to this sign-in.')
    } else {
        $null = $text.AppendLine('| Policy | Grant controls | Applications |')
        $null = $text.AppendLine('| --- | --- | --- |')
        foreach ($p in $Outcome.Enforced) { $null = $text.AppendLine("| $($p.displayName) | $(Get-GrantText -Policy $p) | $(Get-AppText -Policy $p) |") }
    }
    if (@($Outcome.ReportOnly).Count -gt 0) {
        $null = $text.AppendLine()
        $null = $text.AppendLine('**Report-only policies that applied** (not enforced; coverage that depends on them is not counted)')
        $null = $text.AppendLine()
        $null = $text.AppendLine('| Policy | Grant controls | Applications |')
        $null = $text.AppendLine('| --- | --- | --- |')
        foreach ($p in $Outcome.ReportOnly) { $null = $text.AppendLine("| $($p.displayName) | $(Get-GrantText -Policy $p) | $(Get-AppText -Policy $p) |") }
    }
    if (@($Outcome.NotAssessedPolicies).Count -gt 0) {
        $null = $text.AppendLine()
        $null = $text.AppendLine('**Policies What If could not evaluate**')
        $null = $text.AppendLine()
        foreach ($p in $Outcome.NotAssessedPolicies) { $null = $text.AppendLine("- $($p.displayName): $($p.analysisReasons)") }
    }
    if ($Expectation.Note) { $null = $text.AppendLine(); $null = $text.AppendLine("Why this is expected: $($Expectation.Note)") }
    foreach ($n in @($Note | Where-Object { $_ })) { $null = $text.AppendLine(); $null = $text.AppendLine("> $n") }
    $text.ToString()
}
