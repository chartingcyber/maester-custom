function Test-ResSignInsFromUnexpectedCountries {
    <#
    .SYNOPSIS
    Checks that successful sign-ins in the last few days came only from the countries where the organization does business.

    .DESCRIPTION
    Searches the Defender advanced hunting table EntraIdSignInEvents (Microsoft Entra interactive and non-interactive
    sign-ins) for successful sign-ins from any country outside ExpectedCountries (default US and CA) and stops at
    the first MaximumMatches (default 10). Any match fails the check and lists the user, country, app, logon type and
    IP address. A sign-in from an unexpected country is a sign of a stolen password or token. Non-interactive
    sign-ins made for a user by Microsoft services can come from Microsoft datacenters in other countries, so check
    the logon type and app before treating a match as an attack.

    The table needs Microsoft Entra ID P2 and access to Defender advanced hunting. When the tenant has no P2, or
    the query cannot run, or it finds no sign-ins at all, the result is Investigate with the reason and the steps
    to do the same check in the Microsoft Entra admin center. It is never a pass in those cases.
    Sign-ins with no recorded country are not counted.

    To change the countries, set the ExpectedCountries parameter to two-letter ISO 3166-1 codes, for example
    US, CA, GB. The list of codes is at https://www.iso.org/obp/ui/#search/code/.
    #>
    [MaesterTest(
        Id           = 'MP.RESOURCIVE.3005',
        Title        = 'Successful sign-ins come only from expected countries.',
        Product      = 'entra',
        Feature      = 'monitoring',
        Area         = 'access-control',
        ResourceType = 'Tenant',
        Severity     = 'Medium',
        UserImpact   = 'Low',
        ImplementationCost = 'Low',
        Mitre        = ('T1078.004', 'T1110.003'),
        Control      = ('nist-800-53-r5:SI-4', 'nist-800-53-r5:AC-2(12)'),
        Service      = 'Graph',
        Permission   = 'Graph:Scope:ThreatHunting.Read.All'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        # Two-letter ISO 3166-1 codes of the countries where sign-ins are expected, for example US, CA, GB. Default: US, CA.
        [ValidatePattern('^[A-Za-z]{2}$')]
        [string[]] $ExpectedCountries = @('US', 'CA'),

        # How many days of sign-ins to search. Advanced hunting keeps 30 days.
        [ValidateRange(1, 30)]
        [int] $LookbackDays = 7,

        # Stop after this many sign-ins from unexpected countries.
        [ValidateRange(1, 50)]
        [int] $MaximumMatches = 10
    )

    $expected = @($ExpectedCountries | ForEach-Object { $_.Trim().ToUpperInvariant() } | Where-Object { $_ })
    if ($expected.Count -eq 0) { $expected = @('US', 'CA') }
    $expectedText = $expected -join ', '
    $change = "Expected countries: $expectedText. To change them, set the ExpectedCountries parameter (two-letter codes, see https://www.iso.org/obp/ui/#search/code/). Sign-ins with no recorded country are not counted."

    $reason = $null
    $found = $null
    if ((Test-ResLicense -ServicePlan (Get-ResServicePlanName -Product EntraP2)) -eq $false) {
        $reason = 'the tenant does not have Microsoft Entra ID P2, which the advanced hunting sign-in table needs.'
    } else {
        try {
            $found = Find-ResSignInHunting -Kind Country -ExpectedCountry $expected -LookbackDays $LookbackDays -MaximumMatches $MaximumMatches
        } catch {
            $reason = "the advanced hunting query could not run ($((([string]$_.Exception.Message) -split "`n")[0].Trim())). It needs Entra ID P2, the ThreatHunting.Read.All permission and a role with Defender advanced hunting access, such as Security Reader."
        }
        if (-not $reason -and $found.Total -eq 0) {
            $reason = "the advanced hunting table returned no successful sign-ins for the last $LookbackDays days, so it cannot confirm that none came from elsewhere."
        }
    }
    if ($reason) {
        Add-MtTestResultDetail -Result "$(Get-ResSignInManualCheck -Kind Country -Reason $reason -ExpectedText $expectedText -LookbackDays $LookbackDays)`n`n$change" -Investigate
        return $false
    }

    $asOf = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm')
    $how = "Searched $($found.Total) successful sign-ins from the last $LookbackDays days (interactive and non-interactive, oldest $($found.Oldest)) with Defender advanced hunting (EntraIdSignInEvents)."

    if ($found.Matches.Count -eq 0) {
        Add-MtTestResultDetail -Result "Well done. No successful sign-in from outside $expectedText, as of $asOf UTC. $how`n`n$change"
        return $true
    }

    $limit = if ($found.AtLeast) { "At least $($found.Matches.Count) (the search stops at $MaximumMatches)" } else { "$($found.Matches.Count)" }
    $table = "| When (UTC) | User | Country | App | Logon type | IP address |`n| --- | --- | --- | --- | --- | --- |`n" + ((@($found.Matches) | ForEach-Object { "| $($_.createdDateTime) | $($_.userPrincipalName) | $($_.location.countryOrRegion) | $($_.appDisplayName) | $($_.logonType) | $($_.ipAddress) |" }) -join "`n")
    Add-MtTestResultDetail -Result "$limit successful sign-in(s) came from outside $expectedText in the last $LookbackDays days, as of $asOf UTC. $how`n`n$table`n`n$change"
    return $false
}
