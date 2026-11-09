function Test-ResSignInsFromUnexpectedCountries {
    <#
    .SYNOPSIS
    Checks that successful sign-ins in the last few days came only from the countries where the organization does business.

    .DESCRIPTION
    Reads the Entra sign-in log for successful sign-ins in the last LookbackDays days and groups them by country. When
    ExpectedCountries is set, a successful sign-in from any other country fails the check and the users and
    countries are listed. When it is empty the check cannot decide, so it lists the countries with counts and the
    result is Investigate. A sign-in from an unexpected country is a sign of a stolen password or token.

    The sign-in log is slow: a single request can take tens of seconds, and a server-side country filter times out.
    The check therefore reads one small request per day, newest day first, until it has read every day or used its
    time budget, filters by country in PowerShell, and states which days were read and which were not. Sign-in log
    access through Graph needs Entra ID P1 or P2.
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
        # Two-letter codes of the countries where sign-ins are expected, for example US, CA, GB.
        [string[]] $ExpectedCountries = @(),

        # How many days of sign-ins to read.
        [ValidateRange(1, 30)]
        [int] $LookbackDays = 7,

        # The most sign-in records to read for each day, in one request. The newest records of the day are read first.
        [ValidateRange(50, 1000)]
        [int] $MaximumSignInsPerDay = 200,

        # Stop starting new days after this many seconds. A request already running is not interrupted.
        [ValidateRange(30, 1800)]
        [int] $TimeBudgetSeconds = 180
    )

    Assert-ResLicense -Name 'Microsoft Entra ID P1' -ServicePlan (Get-ResServicePlanName -Product EntraP1)

    # One request per day, newest first. The date range is the only server-side filter: combined filters on the
    # sign-in log can take minutes. Success and interactive are filtered here.
    $clock = [System.Diagnostics.Stopwatch]::StartNew()
    $today = (Get-Date).ToUniversalTime().Date
    $days = [System.Collections.Generic.List[object]]::new()
    $signIns = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $LookbackDays; $i++) {
        $dayStart = $today.AddDays(-$i)
        $label = $dayStart.ToString('yyyy-MM-dd')
        if ($clock.Elapsed.TotalSeconds -ge $TimeBudgetSeconds) {
            $days.Add([pscustomobject]@{ Day = $label; State = 'Not read (time budget used)'; Rows = 0 })
            continue
        }
        $from = $dayStart.ToString('yyyy-MM-ddTHH:mm:ssZ')
        $to = $dayStart.AddDays(1).ToString('yyyy-MM-ddTHH:mm:ssZ')
        try {
            $page = Get-ResGraphPage (Invoke-MtGraphRequest -RelativeUri 'auditLogs/signIns' -ApiVersion v1.0 -Filter "createdDateTime ge $from and createdDateTime lt $to" -Select userPrincipalName, location, createdDateTime, appDisplayName, isInteractive, status -QueryParameters @{ '$top' = $MaximumSignInsPerDay } -DisablePaging -ErrorAction Stop)
            $rows = @($page.Rows)
        } catch {
            if ([string]$_.Exception.Message -match 'Timeout|timed out|canceled') {
                $days.Add([pscustomobject]@{ Day = $label; State = 'Not read (request timed out)'; Rows = 0 })
                continue
            }
            Resolve-ResGraphError -ErrorRecord $_ -Feature 'the sign-in log' -Requires 'AuditLog.Read.All and Reports Reader, Security Reader or Global Reader'
        }
        $kept = @($rows | Where-Object { $_.isInteractive -eq $true -and $_.status -and $_.status.errorCode -eq 0 })
        foreach ($row in $kept) { $signIns.Add($row) }
        $state = if ($page.HasMore -or @($rows).Count -ge $MaximumSignInsPerDay) { "Partly read (newest $MaximumSignInsPerDay of the day)" } else { 'Read' }
        $days.Add([pscustomobject]@{ Day = $label; State = $state; Rows = @($rows).Count })
    }

    $unread = @($days | Where-Object { $_.State -like 'Not read*' })
    $partial = @($days | Where-Object { $_.State -like 'Partly*' })
    $daysTable = "| Day (UTC) | Coverage | Records read |`n| --- | --- | --- |`n" + ((@($days) | ForEach-Object { "| $($_.Day) | $($_.State) | $($_.Rows) |" }) -join "`n")
    if ($unread.Count -eq $days.Count) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason "Not assessed: no day of the sign-in log could be read within the time budget of $TimeBudgetSeconds seconds, or the requests timed out."
    }
    $signIns = @($signIns)
    if ($signIns.Count -eq 0) {
        Add-MtTestResultDetail -SkippedBecause NotApplicable
    }

    $expected = @($ExpectedCountries | ForEach-Object { $_.Trim().ToUpperInvariant() } | Where-Object { $_ })
    $byCountry = $signIns | Group-Object { [string]$_.location.countryOrRegion } | Sort-Object Count -Descending
    $asOf = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm')
    $coverage = if ($unread.Count -gt 0 -or $partial.Count -gt 0) { " Coverage is incomplete: $($unread.Count) of $($days.Count) day(s) were not read and $($partial.Count) were only partly read, so sign-ins outside the records read are not assessed." } else { '' }
    $scope = "Read $($signIns.Count) successful interactive sign-ins from the last $LookbackDays days as of $asOf UTC.$coverage"

    $countryTable = "| Country | Sign-ins |`n| --- | --- |`n" + ((@($byCountry) | Select-Object -First 30 | ForEach-Object { "| $(if ($_.Name) { $_.Name } else { 'unknown' }) | $($_.Count) |" }) -join "`n")

    if ($expected.Count -eq 0) {
        Add-MtTestResultDetail -Result "$scope Set the ExpectedCountries parameter to the countries where the organization has staff or customers, so the check can decide.`n`n$countryTable`n`n$daysTable" -Investigate
        return $false
    }

    $unexpected = @($signIns | Where-Object { $_.location.countryOrRegion -and ([string]$_.location.countryOrRegion).ToUpperInvariant() -notin $expected })
    if ($unexpected.Count -eq 0) {
        Add-MtTestResultDetail -Result "Well done. All successful sign-ins came from the expected countries ($($expected -join ', ')). $scope`n`n$countryTable`n`n$daysTable"
        return $true
    }
    $users = $unexpected | Group-Object userPrincipalName | Sort-Object Count -Descending | Select-Object -First 50
    $table = "| User | Sign-ins from unexpected countries | Countries |`n| --- | --- | --- |`n" + ((@($users) | ForEach-Object { "| $($_.Name) | $($_.Count) | $((@($_.Group | ForEach-Object { $_.location.countryOrRegion } | Select-Object -Unique)) -join ', ') |" }) -join "`n")
    Add-MtTestResultDetail -Result "$($unexpected.Count) successful sign-in(s) came from outside $($expected -join ', '). $scope`n`n$table`n`n$daysTable"
    return $false
}
