function Test-ResSignInsFromUnexpectedCountries {
    <#
    .SYNOPSIS
    Checks that successful sign-ins in the last few days came only from the countries where the organization does business.

    .DESCRIPTION
    Searches the Entra sign-in log for successful interactive sign-ins from any country outside ExpectedCountries
    (default US and CA) and stops at the first MaximumMatches (default 10). Any match fails the check and lists the
    users, countries and apps. A sign-in from an unexpected country is a sign of a stolen password or token.

    The search asks Graph for the matches only (one request over the whole period). If Graph refuses that filter or
    it times out, the check reads one small request per day instead and filters here. A result of no matches is a
    pass only when the whole period was searched; otherwise it is Investigate, with the days that were not read.
    Sign-ins with no recorded country are not counted. Sign-in log access through Graph needs Entra ID P1 or P2.

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
        License      = 'AAD_PREMIUM',
        Permission   = 'Graph:Scope:AuditLog.Read.All',
        LongRunning
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        # Two-letter ISO 3166-1 codes of the countries where sign-ins are expected, for example US, CA, GB. Default: US, CA.
        [ValidatePattern('^[A-Za-z]{2}$')]
        [string[]] $ExpectedCountries = @('US', 'CA'),

        # How many days of sign-ins to search, including today.
        [ValidateRange(1, 30)]
        [int] $LookbackDays = 7,

        # Stop after this many sign-ins from unexpected countries.
        [ValidateRange(1, 50)]
        [int] $MaximumMatches = 10,

        # If the check has to read day by day: the most records to read for each day. The newest records are read first.
        [ValidateRange(50, 1000)]
        [int] $MaximumSignInsPerDay = 200,

        # If the check has to read day by day: stop starting new days after this many seconds.
        [ValidateRange(30, 3600)]
        [int] $TimeBudgetSeconds = 600
    )

    Assert-ResLicense -Name 'Microsoft Entra ID P1' -ServicePlan (Get-ResServicePlanName -Product EntraP1)

    $expected = @($ExpectedCountries | ForEach-Object { $_.Trim().ToUpperInvariant() } | Where-Object { $_ })
    if ($expected.Count -eq 0) { $expected = @('US', 'CA') }
    $expectedText = $expected -join ', '

    $found = Find-ResSignIn -Kind Country -ExpectedCountry $expected -LookbackDays $LookbackDays -MaximumMatches $MaximumMatches -MaximumSignInsPerDay $MaximumSignInsPerDay -TimeBudgetSeconds $TimeBudgetSeconds

    $unread = @($found.Days | Where-Object { $_.State -like 'Not read*' })
    if ($found.Mode -eq 'PerDay' -and $unread.Count -eq @($found.Days).Count) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason "Not assessed: no day of the sign-in log could be read within the time budget of $TimeBudgetSeconds seconds, or the requests timed out."
    }

    $asOf = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm')
    $daysTable = "| Day (UTC) | Coverage | Records read |`n| --- | --- | --- |`n" + ((@($found.Days) | ForEach-Object { "| $($_.Day) | $($_.State) | $($_.Rows) |" }) -join "`n")
    $how = if ($found.Mode -eq 'ServerFilter') { 'Searched the whole period with a server-side filter.' } else { "Read the log day by day because the server-side filter was not usable. $($found.FallbackReason)" }
    $change = "Expected countries: $expectedText. To change them, set the ExpectedCountries parameter (two-letter codes, see https://www.iso.org/obp/ui/#search/code/). Sign-ins with no recorded country are not counted."

    if ($found.Matches.Count -eq 0) {
        if ($found.Complete) {
            Add-MtTestResultDetail -Result "Well done. No successful interactive sign-in from outside $expectedText in the last $LookbackDays days, as of $asOf UTC. $how`n`n$change"
            return $true
        }
        Add-MtTestResultDetail -Result "No sign-in from outside $expectedText was found in the records read, but this is not a pass: coverage is incomplete. $how Raise TimeBudgetSeconds or MaximumSignInsPerDay, or check the sign-in log in the Entra admin center.`n`n$change`n`n$daysTable" -Investigate
        return $false
    }

    $limit = if ($found.AtLeast) { "At least $($found.Matches.Count) (the search stops at $MaximumMatches)" } else { "$($found.Matches.Count)" }
    $table = "| When (UTC) | User | Country | App | IP address |`n| --- | --- | --- | --- | --- |`n" + ((@($found.Matches) | ForEach-Object { "| $($_.createdDateTime) | $($_.userPrincipalName) | $($_.location.countryOrRegion) | $($_.appDisplayName) | $($_.ipAddress) |" }) -join "`n")
    Add-MtTestResultDetail -Result "$limit successful interactive sign-in(s) came from outside $expectedText in the last $LookbackDays days, as of $asOf UTC. $how`n`n$table`n`n$change"
    return $false
}
