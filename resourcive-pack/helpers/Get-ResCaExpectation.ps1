function Get-ResCaExpectation {
    <#
    .SYNOPSIS
    Decides what a scenario is expected to result in, and how severe a miss is.

    .DESCRIPTION
    Defaults:
    - Legacy client types (exchangeActiveSync, other): Block. Critical for a privileged persona, otherwise High.
    - Privileged persona, any other scenario: MFA or stronger. Critical. Phishing-resistant is noted, not required.
    - Member or guest, Microsoft 365 application, modern client: MFA or stronger. High.
    - Sign-in risk High, user risk High (Entra ID P2 only): MFA or stronger for sign-in risk, Remediate (block,
      password change or MFA) for user risk. High.
    - Everything else (members and guests on admin portals, Azure, other applications and user actions):
      Info, which is reported for review and never fails.
    - An emergency access account is excluded from policies by design: Info.

    A desired-state file can override these. Its Rules are tried in order and the first match wins; a rule can match
    Persona (Privileged, Member, Guest or *), Client, App (name, key or ID), Platform, Location (home, outside or a
    key), Action and Axis, each a string, a list of strings or *, and sets Expect (Block, MFA, PhishingResistant,
    Remediate or Info) and Severity. Returns Expect, Severity, Source (Default or Desired) and Note.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        # The scenario from New-ResCaScenario.
        [Parameter(Mandatory)]
        $Scenario,

        # The parsed desired-state file, or $null.
        [AllowNull()]
        $Desired
    )

    $persona = $Scenario.Persona
    function Test-RuleValue {
        param($Value, $Wanted)
        if ($null -eq $Wanted) { return $true }
        $list = @($Wanted)
        if ($list.Count -eq 0 -or $list -contains '*') { return $true }
        foreach ($w in $list) { if ([string]$Value -ieq [string]$w) { return $true } }
        $false
    }
    function New-Expectation { param($Expect, $Severity, $Note) [pscustomobject]@{ Expect = $Expect; Severity = $Severity; Source = 'Default'; Note = $Note } }

    foreach ($rule in @($Desired.Rules)) {
        if (-not $rule) { continue }
        $appHit = (Test-RuleValue $Scenario.App.Name $rule.App) -or (Test-RuleValue $Scenario.App.Key $rule.App) -or (Test-RuleValue $Scenario.App.Id $rule.App)
        if ((Test-RuleValue $persona.Kind $rule.Persona) -and (Test-RuleValue $Scenario.ClientAppType $rule.Client) -and $appHit -and
            (Test-RuleValue $Scenario.DevicePlatform $rule.Platform) -and (Test-RuleValue $Scenario.LocationKey $rule.Location) -and
            (Test-RuleValue $Scenario.UserAction $rule.Action) -and (Test-RuleValue $Scenario.Axis $rule.Axis)) {
            $severity = if ($rule.Severity) { [string]$rule.Severity } else { 'High' }
            return [pscustomobject]@{ Expect = [string]$rule.Expect; Severity = $severity; Source = 'Desired'; Note = [string]$rule.Note }
        }
    }

    $legacy = $Scenario.ClientAppType -in @('exchangeActiveSync', 'other')

    if ($persona.IsEmergencyAccess) {
        return New-Expectation 'Info' 'Info' 'Emergency access account: Conditional Access excludes these accounts by design, so the result is shown for review only.'
    }
    if ($legacy) {
        return New-Expectation 'Block' $(if ($persona.Kind -eq 'Privileged') { 'Critical' } else { 'High' }) 'Legacy authentication clients cannot do MFA and must be blocked.'
    }
    if ($Scenario.SignInRiskLevel -ne 'None') { return New-Expectation 'MFA' 'High' 'A high sign-in risk must require MFA or stronger.' }
    if ($Scenario.UserRiskLevel -ne 'None') { return New-Expectation 'Remediate' 'High' 'A high user risk must be blocked or remediated with a password change or MFA.' }
    if ($persona.Kind -eq 'Privileged') { return New-Expectation 'MFA' 'Critical' 'A privileged user must satisfy MFA or stronger on every application and client.' }
    if ($Scenario.App -and $Scenario.App.Group -eq 'M365' -and -not $Scenario.UserAction) {
        return New-Expectation 'MFA' 'High' 'Members and guests must satisfy MFA or stronger on Microsoft 365 applications.'
    }
    New-Expectation 'Info' 'Info' 'Informational: no default expectation for this scenario. Add a rule to the desired-state file to turn it into a check.'
}
