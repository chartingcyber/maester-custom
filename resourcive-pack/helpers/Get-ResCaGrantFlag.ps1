function Get-ResCaGrantFlag {
    <#
    .SYNOPSIS
    Turns the grant controls of one Conditional Access policy into the set of guarantees a user must meet.

    .DESCRIPTION
    Flags: Block, MFA, PhishingResistant, Device (compliantDevice or domainJoinedDevice), App (approvedApplication
    or compliantApplication), PasswordChange, TermsOfUse. PhishingResistant implies MFA.

    The operator decides how the controls combine. With AND the user must meet every control, so the flags are
    the union. With OR the user picks the easiest alternative, so only the guarantees that every alternative
    gives remain: the flags are the intersection (the weakest alternative decides). An authentication strength
    counts as an alternative of its own. A policy with no grant controls (session controls only) has no flags.
    Returns a string array of flags.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        # The grantControls object of the policy, or $null.
        [AllowNull()]
        $GrantControl
    )

    if (-not $GrantControl) { return [string[]]@() }

    $alternatives = [System.Collections.Generic.List[string[]]]::new()
    foreach ($control in @($GrantControl.builtInControls)) {
        switch ([string]$control) {
            'block' { $alternatives.Add([string[]]@('Block')) }
            'mfa' { $alternatives.Add([string[]]@('MFA')) }
            'compliantDevice' { $alternatives.Add([string[]]@('Device')) }
            'domainJoinedDevice' { $alternatives.Add([string[]]@('Device')) }
            'approvedApplication' { $alternatives.Add([string[]]@('App')) }
            'compliantApplication' { $alternatives.Add([string[]]@('App')) }
            'passwordChange' { $alternatives.Add([string[]]@('PasswordChange', 'MFA')) }
            default { }
        }
    }
    if (@($GrantControl.termsOfUse | Where-Object { $_ }).Count -gt 0) { $alternatives.Add([string[]]@('TermsOfUse')) }
    if (@($GrantControl.customAuthenticationFactors | Where-Object { $_ }).Count -gt 0) { $alternatives.Add([string[]]@('MFA')) }

    $strength = $GrantControl.authenticationStrength
    if ($strength) {
        $phishingResistant = @('windowsHelloForBusiness', 'fido2', 'x509CertificateMultiFactor')
        $combinations = @($strength.allowedCombinations | Where-Object { $_ })
        $builtInPhishingResistant = ([string]$strength.id -eq '00000000-0000-0000-0000-000000000004') -or ([string]$strength.displayName -match '^Phishing-resistant MFA')
        if ($builtInPhishingResistant -or ($combinations.Count -gt 0 -and @($combinations | Where-Object { $phishingResistant -notcontains $_ }).Count -eq 0)) {
            $alternatives.Add([string[]]@('MFA', 'PhishingResistant'))
        } else {
            $alternatives.Add([string[]]@('MFA'))
        }
    }

    if ($alternatives.Count -eq 0) { return [string[]]@() }
    if ($alternatives.Count -eq 1) { return [string[]]@($alternatives[0] | Select-Object -Unique) }

    $operator = if ([string]$GrantControl.operator -eq 'OR') { 'OR' } else { 'AND' }
    if ($operator -eq 'AND') {
        return [string[]]@($alternatives | ForEach-Object { $_ } | Select-Object -Unique)
    }
    $common = @($alternatives[0])
    for ($i = 1; $i -lt $alternatives.Count; $i++) {
        $alt = $alternatives[$i]
        $common = @($common | Where-Object { $alt -contains $_ })
    }
    [string[]]@($common | Select-Object -Unique)
}
