function Test-ResSignInMatch {
    <#
    .SYNOPSIS
    Says whether one sign-in log record is a finding for the sign-in checks.

    .DESCRIPTION
    Kind Country: a successful interactive sign-in whose country is known and is not in ExpectedCountry.
    Kind Legacy: a successful sign-in whose client app is named and is not a browser, a modern mobile or desktop
    client, or Unknown (the log did not record the client). A sign-in that failed never matches.
    The same rule runs on the server filter's results and on the records read day by day, so both paths agree.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        # One record from auditLogs/signIns.
        [Parameter(Mandatory)]
        $SignIn,

        [Parameter(Mandatory)]
        [ValidateSet('Country', 'Legacy')]
        [string] $Kind,

        # Two-letter country codes that are expected. Used by Kind Country.
        [string[]] $ExpectedCountry = @()
    )

    if (-not $SignIn.status -or $SignIn.status.errorCode -ne 0) { return $false }

    if ($Kind -eq 'Country') {
        if ($SignIn.isInteractive -ne $true) { return $false }
        $country = [string]$SignIn.location.countryOrRegion
        if (-not $country) { return $false }
        $expected = @($ExpectedCountry | ForEach-Object { ([string]$_).Trim().ToUpperInvariant() } | Where-Object { $_ })
        return ($country.ToUpperInvariant() -notin $expected)
    }

    $app = [string]$SignIn.clientAppUsed
    return [bool]($app -and $app -notin @('Browser', 'Mobile Apps and Desktop clients', 'Unknown'))
}
