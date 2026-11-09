function Test-ResCaExpectation {
    <#
    .SYNOPSIS
    Compares the observed outcome of a scenario with its expectation.

    .DESCRIPTION
    Returns Status (Pass, Fail or Investigate), Reason and Severity (Low for a de facto block, else $null: the
    severity the instance source set stands).
    - NotAssessed outcomes are Investigate, never Pass. That includes a What If call that failed after retries.
    - A legacy client type (exchangeActiveSync, other) cannot satisfy MFA, a device requirement or an approved
      client app requirement. When Block is expected and the outcome is MFA, PhishingResistant, DeviceRequired or
      AppRequired, the client is blocked in effect: Pass with the note "de facto block, an explicit block policy is
      still recommended" and Severity Low. Literal NoControl on a legacy client stays the failure.
    - AppRequired (approved client app or app protection) meets no MFA expectation: Investigate, like a device
      requirement without MFA.
    - Expect Block passes on Block. Expect MFA passes on MFA, PhishingResistant or Block; DeviceRequired alone is
      Investigate unless DeviceRequiredSatisfiesMfa is set. Expect PhishingResistant passes on PhishingResistant or
      Block. Expect Remediate passes on Block, or when the flags hold PasswordChange or MFA.
    - A scenario that would meet the expectation only through a report-only policy is Investigate, not Pass.
    - Expect Info is always Investigate (reported for review, with Info severity).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        # The outcome from Get-ResCaOutcome.
        [Parameter(Mandatory)]
        $Outcome,

        # The expectation from Get-ResCaExpectation.
        [Parameter(Mandatory)]
        $Expectation,

        # Treat a device requirement without MFA as meeting an MFA expectation.
        [switch] $DeviceRequiredSatisfiesMfa,

        # The client app type of the scenario. Legacy ones (exchangeActiveSync, other) cannot satisfy MFA or device controls.
        [string] $ClientAppType = ''
    )

    function New-Verdict { param($Status, $Reason, $Severity = $null) [pscustomobject]@{ Status = $Status; Reason = $Reason; Severity = $Severity } }
    if ($Expectation.Expect -eq 'Info') { return New-Verdict 'Investigate' 'Informational scenario, shown for review.' }
    if ($Outcome.Failure) {
        return New-Verdict 'Investigate' "Not assessed: the What If call failed after retries ($($Outcome.Failure)). Not counted as a pass or a failure; run the test again."
    }
    if ($Outcome.Class -eq 'NotAssessed') {
        $names = @($Outcome.NotAssessedPolicies | ForEach-Object { '{0} ({1})' -f $_.displayName, $_.analysisReasons }) -join '; '
        return New-Verdict 'Investigate' "Not assessed: What If could not evaluate $names. Not counted as a pass."
    }

    $class = $Outcome.Class
    $flags = @($Outcome.Flags)
    $met = switch ($Expectation.Expect) {
        'Block' { $class -eq 'Block' }
        'MFA' { $class -in @('Block', 'MFA', 'PhishingResistant') }
        'PhishingResistant' { $class -in @('Block', 'PhishingResistant') }
        'Remediate' { $class -eq 'Block' -or $flags -contains 'PasswordChange' -or $flags -contains 'MFA' }
        default { $false }
    }
    $legacy = $ClientAppType -in @('exchangeActiveSync', 'other')
    if (-not $met -and $legacy -and $Expectation.Expect -eq 'Block' -and $class -in @('MFA', 'PhishingResistant', 'DeviceRequired', 'AppRequired')) {
        return New-Verdict 'Pass' "Observed $class on a legacy client, which cannot satisfy it: de facto block, an explicit block policy is still recommended." 'Low'
    }
    if ($met) { return New-Verdict 'Pass' "Observed $class meets the expectation $($Expectation.Expect)." }

    if ($Expectation.Expect -eq 'MFA' -and $class -eq 'DeviceRequired') {
        if ($DeviceRequiredSatisfiesMfa) { return New-Verdict 'Pass' 'A compliant or joined device is required, which the desired state accepts in place of MFA.' }
        return New-Verdict 'Investigate' 'A compliant or joined device is required but MFA is not. Decide whether the device control is enough.'
    }
    if ($Expectation.Expect -eq 'MFA' -and $class -eq 'AppRequired') {
        return New-Verdict 'Investigate' 'An approved client app or app protection policy is required but MFA is not. Decide whether the app control is enough.'
    }
    if ($Outcome.CoverageDependsOnReportOnly) {
        return New-Verdict 'Investigate' "Coverage depends on report-only policies: enforced policies give $class, report-only policies would give $($Outcome.ReportOnlyClass)."
    }
    New-Verdict 'Fail' "Observed $class, expected $($Expectation.Expect)."
}
