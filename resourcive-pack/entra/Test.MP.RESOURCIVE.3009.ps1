function Test-ResLegacyAuthenticationSignIns {
    <#
    .SYNOPSIS
    Checks the sign-in log for successful sign-ins that used a legacy authentication protocol in the last few days.

    .DESCRIPTION
    Legacy protocols (IMAP, POP, SMTP AUTH, Exchange ActiveSync with basic authentication, and the other
    "other clients") cannot do MFA, so a password is enough. A Conditional Access policy that blocks them is checked by
    MT.1009, MT.1010 and CISA MS.AAD.1.1 and simulated by MT.1033. This check looks at what actually happened: it
    searches for successful sign-ins whose client app is not a browser and not a modern mobile or desktop client,
    and stops at the first MaximumMatches (default 10). Any match fails the check.

    Legacy protocols usually sign in non-interactively, and the v1.0 sign-in log returns only interactive
    sign-ins, so the search uses the beta log with a signInEventTypes filter. If the beta log cannot be read, the
    check reads v1.0 instead, says that non-interactive sign-ins were not assessed, and cannot pass.

    The search asks Graph for the matches only (one request over the whole period). If Graph refuses that filter
    or it times out, the check reads one small request per day. A result of no matches is a pass only when the
    whole period was searched; otherwise it is Investigate, with the days that were not read.

    Entra keeps the sign-in log for 30 days with Entra ID P1 or P2. Sign-in log access through Graph needs a premium
    licence.
    #>
    [MaesterTest(
        Id           = 'MP.RESOURCIVE.3009',
        Title        = 'No successful sign-in used a legacy authentication protocol in the recent sign-in log.',
        Product      = 'entra',
        Feature      = 'monitoring',
        Area         = 'authentication',
        ResourceType = 'User',
        Severity     = 'High',
        UserImpact   = 'Medium',
        ImplementationCost = 'Medium',
        Mitre        = ('T1110.003', 'T1078.004'),
        Control      = ('nist-800-53-r5:IA-2', 'nist-800-53-r5:AC-17'),
        Service      = 'Graph',
        License      = 'AAD_PREMIUM',
        Permission   = 'Graph:Scope:AuditLog.Read.All',
        LongRunning
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        # How many days of sign-ins to search, including today. Entra keeps 30 days.
        [ValidateRange(1, 30)]
        [int] $LookbackDays = 7,

        # Stop after this many legacy sign-ins.
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

    $found = Find-ResSignIn -Kind Legacy -LookbackDays $LookbackDays -MaximumMatches $MaximumMatches -MaximumSignInsPerDay $MaximumSignInsPerDay -TimeBudgetSeconds $TimeBudgetSeconds

    $unread = @($found.Days | Where-Object { $_.State -like 'Not read*' })
    if ($found.Mode -eq 'PerDay' -and $unread.Count -eq @($found.Days).Count) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason "Not assessed: no day of the sign-in log could be read within the time budget of $TimeBudgetSeconds seconds, or the requests timed out."
    }

    $asOf = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm')
    $daysTable = "| Day (UTC) | Coverage | Records read |`n| --- | --- | --- |`n" + ((@($found.Days) | ForEach-Object { "| $($_.Day) | $($_.State) | $($_.Rows) |" }) -join "`n")
    $how = if ($found.Mode -eq 'ServerFilter') { 'Searched the whole period with a server-side filter.' } else { "Read the log day by day because the server-side filter was not usable. $($found.FallbackReason)" }
    $nonInteractiveNote = if ($found.NonInteractiveAssessed -eq $false) { ' Non-interactive sign-ins, where legacy protocols usually appear, were not assessed because the beta sign-in log could not be read.' } else { '' }

    if ($found.Matches.Count -eq 0) {
        if ($found.Complete) {
            Add-MtTestResultDetail -Result "Well done. No successful sign-in used a legacy authentication protocol in the last $LookbackDays days (interactive and non-interactive), as of $asOf UTC. $how"
            return $true
        }
        Add-MtTestResultDetail -Result "No legacy sign-in was found in the records read, but this is not a pass: coverage is incomplete. $how$nonInteractiveNote Raise TimeBudgetSeconds or MaximumSignInsPerDay, or check the sign-in log in the Entra admin center filtered by Client app.`n`n$daysTable" -Investigate
        return $false
    }

    $limit = if ($found.AtLeast) { "At least $($found.Matches.Count) (the search stops at $MaximumMatches)" } else { "$($found.Matches.Count)" }
    $table = "| When (UTC) | User | Protocol | App | IP address |`n| --- | --- | --- | --- | --- |`n" + ((@($found.Matches) | ForEach-Object { "| $($_.createdDateTime) | $($_.userPrincipalName) | $($_.clientAppUsed) | $($_.appDisplayName) | $($_.ipAddress) |" }) -join "`n")
    Add-MtTestResultDetail -Result "$limit successful sign-in(s) used a legacy authentication protocol in the last $LookbackDays days, as of $asOf UTC. $how$nonInteractiveNote`n`n$table"
    return $false
}
