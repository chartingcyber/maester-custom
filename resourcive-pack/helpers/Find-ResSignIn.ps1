function Find-ResSignIn {
    <#
    .SYNOPSIS
    Finds the first few sign-in log records that are a finding, and says how much of the log was searched.

    .DESCRIPTION
    The sign-in log is slow. By default the search reads one small request per day, newest first, and filters here
    with Test-ResSignInMatch. With -ServerFilter it first tries one request over the whole lookback period with the
    finding as a server-side filter and a small $top, so Graph stops after MaximumMatches records; that request
    ran into the 300 second HTTP timeout on the interactive log, so it is opt-in. When it is refused or times out,
    the search falls back to the day-by-day read. The search stops as soon as MaximumMatches records are found, or when the
       time budget is used. Days that were not read, or only partly read, are listed, and Complete is false.

    Kind Country searches the v1.0 log, which holds interactive user sign-ins. Kind Legacy searches the beta log
    with a signInEventTypes filter, because legacy protocols (IMAP, POP, SMTP AUTH, Exchange ActiveSync) usually
    sign in non-interactively and the v1.0 log does not return those. If the beta log cannot be read, the
    search falls back to v1.0, NonInteractiveAssessed is false and Complete is false, so a clean result is never a pass.

    Returns an object with Matches (at most MaximumMatches records), AtLeast (true when the limit was reached, so
    there may be more), Mode (ServerFilter or PerDay), Days (a coverage row per day), Complete, ReadCount,
    NonInteractiveAssessed (Kind Legacy only) and FallbackReason.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Country', 'Legacy')]
        [string] $Kind,

        # Two-letter country codes that are expected. Used by Kind Country.
        [string[]] $ExpectedCountry = @(),

        # How many days of the log to search, including today.
        [ValidateRange(1, 30)]
        [int] $LookbackDays = 7,

        # Stop after this many matching records.
        [ValidateRange(1, 50)]
        [int] $MaximumMatches = 10,

        # Day by day, the most records to read per day. The newest records of the day are read first.
        [ValidateRange(50, 1000)]
        [int] $MaximumSignInsPerDay = 200,

        # Day by day, stop starting new days after this many seconds. A request already running is not interrupted.
        [ValidateRange(30, 3600)]
        [int] $TimeBudgetSeconds = 600,

        # Try one server-side filtered request over the whole period first. Off by default: on the interactive log it
        # was seen to run into the 300 second HTTP timeout, which wastes five minutes before the day-by-day read.
        [switch] $ServerFilter
    )

    $expected = @($ExpectedCountry | ForEach-Object { ([string]$_).Trim().ToUpperInvariant() } | Where-Object { $_ })
    $select = if ($Kind -eq 'Country') {
        @('userPrincipalName', 'location', 'createdDateTime', 'appDisplayName', 'ipAddress', 'isInteractive', 'status')
    } else {
        @('userPrincipalName', 'clientAppUsed', 'createdDateTime', 'appDisplayName', 'ipAddress', 'status')
    }
    $eventFilter = "(signInEventTypes/any(t: t eq 'interactiveUser') or signInEventTypes/any(t: t eq 'nonInteractiveUser'))"
    $api = if ($Kind -eq 'Legacy') { 'beta' } else { 'v1.0' }
    $nonInteractive = if ($Kind -eq 'Legacy') { $true } else { $null }
    $today = (Get-Date).ToUniversalTime().Date
    $start = $today.AddDays(-($LookbackDays - 1))
    $stamp = 'yyyy-MM-ddTHH:mm:ssZ'

    $licenceText = 'premium license|AadPremiumLicenseRequired|RequestFromNonPremiumTenantOrB2CTenant|not licensed|license is required'
    $retryText = 'Timeout|timed out|canceled|Unsupported|not supported|Invalid filter|Invalid query|BadRequest|Bad Request|\b400\b'

    $kindFilter = if ($Kind -eq 'Country') {
        (@("isInteractive eq true", "status/errorCode eq 0") + @($expected | ForEach-Object { "location/countryOrRegion ne '$_'" })) -join ' and '
    } else {
        "status/errorCode eq 0 and clientAppUsed ne 'Browser' and clientAppUsed ne 'Mobile Apps and Desktop clients' and clientAppUsed ne 'Unknown'"
    }

    $fallbackReason = $null

    # 1. One server-side search over the whole period (opt-in).
    $wholePeriodFilter = "createdDateTime ge $($start.ToString($stamp)) and $kindFilter"
    if ($Kind -eq 'Legacy') { $wholePeriodFilter += " and $eventFilter" }
    if ($ServerFilter) { try {
        $page = Get-ResGraphPage (Invoke-MtGraphRequest -RelativeUri 'auditLogs/signIns' -ApiVersion $api -Filter $wholePeriodFilter -Select $select -QueryParameters @{ '$top' = $MaximumMatches } -DisablePaging -ErrorAction Stop)
        $rows = @($page.Rows)
        $hits = @($rows | Where-Object { Test-ResSignInMatch -SignIn $_ -Kind $Kind -ExpectedCountry $expected } | Select-Object -First $MaximumMatches)
        return [pscustomobject]@{
            Matches                = $hits
            AtLeast                = ($rows.Count -ge $MaximumMatches -or $page.HasMore)
            Mode                   = 'ServerFilter'
            Days                   = @([pscustomobject]@{ Day = "$($start.ToString('yyyy-MM-dd')) to $($today.ToString('yyyy-MM-dd'))"; State = 'Searched with a server-side filter'; Rows = $rows.Count })
            Complete               = $true
            ReadCount              = $null
            NonInteractiveAssessed = $nonInteractive
            FallbackReason         = $null
        }
    } catch {
        $text = "$($_.Exception.Message) $($_.ErrorDetails.Message)"
        if ($text -match $licenceText -or $text -notmatch $retryText) {
            Resolve-ResGraphError -ErrorRecord $_ -Feature 'the sign-in log' -Requires 'AuditLog.Read.All and Reports Reader, Security Reader or Global Reader'
        }
        $fallbackReason = "The server-side filter was not usable ($(($text -replace '\s+', ' ').Trim().Substring(0, [math]::Min(120, ($text -replace '\s+', ' ').Trim().Length))))."
    } }

    # 2. One small request per day, newest first, filtered here.
    $clock = [System.Diagnostics.Stopwatch]::StartNew()
    $days = [System.Collections.Generic.List[object]]::new()
    $found = [System.Collections.Generic.List[object]]::new()
    $readCount = 0
    for ($i = 0; $i -lt $LookbackDays; $i++) {
        $dayStart = $today.AddDays(-$i)
        $label = $dayStart.ToString('yyyy-MM-dd')
        if ($found.Count -ge $MaximumMatches) {
            $days.Add([pscustomobject]@{ Day = $label; State = 'Not needed (enough matches found)'; Rows = 0 })
            continue
        }
        if ($clock.Elapsed.TotalSeconds -ge $TimeBudgetSeconds) {
            $days.Add([pscustomobject]@{ Day = $label; State = 'Not read (time budget used)'; Rows = 0 })
            continue
        }
        $dayFilter = "createdDateTime ge $($dayStart.ToString($stamp)) and createdDateTime lt $($dayStart.AddDays(1).ToString($stamp))"
        $dayRows = $null
        $hasMore = $false
        for ($attempt = 0; $attempt -lt 2 -and $null -eq $dayRows; $attempt++) {
            $filter = if ($api -eq 'beta') { "$dayFilter and $eventFilter" } else { $dayFilter }
            try {
                $dayPage = Get-ResGraphPage (Invoke-MtGraphRequest -RelativeUri 'auditLogs/signIns' -ApiVersion $api -Filter $filter -Select $select -QueryParameters @{ '$top' = $MaximumSignInsPerDay } -DisablePaging -ErrorAction Stop)
                $dayRows = @($dayPage.Rows)
                $hasMore = $dayPage.HasMore
            } catch {
                $text = "$($_.Exception.Message) $($_.ErrorDetails.Message)"
                if ($text -match 'Timeout|timed out|canceled') {
                    $days.Add([pscustomobject]@{ Day = $label; State = 'Not read (request timed out)'; Rows = 0 })
                    $dayRows = @()
                    $hasMore = $null
                } elseif ($api -eq 'beta' -and $text -notmatch $licenceText -and $text -match $retryText) {
                    # The beta log or its event filter cannot be used: read the v1.0 log, which has no non-interactive sign-ins.
                    $api = 'v1.0'
                    $nonInteractive = $false
                } else {
                    Resolve-ResGraphError -ErrorRecord $_ -Feature 'the sign-in log' -Requires 'AuditLog.Read.All and Reports Reader, Security Reader or Global Reader'
                }
            }
        }
        if ($null -eq $hasMore) { continue }
        $readCount += $dayRows.Count
        foreach ($row in $dayRows) {
            if ($found.Count -lt $MaximumMatches -and (Test-ResSignInMatch -SignIn $row -Kind $Kind -ExpectedCountry $expected)) { $found.Add($row) }
        }
        $state = if ($hasMore -or $dayRows.Count -ge $MaximumSignInsPerDay) { "Partly read (newest $MaximumSignInsPerDay of the day)" } else { 'Read' }
        $days.Add([pscustomobject]@{ Day = $label; State = $state; Rows = $dayRows.Count })
    }

    $incomplete = @($days | Where-Object { $_.State -like 'Not read*' -or $_.State -like 'Partly*' })
    [pscustomobject]@{
        Matches                = @($found)
        AtLeast                = ($found.Count -ge $MaximumMatches)
        Mode                   = 'PerDay'
        Days                   = @($days)
        Complete               = ($incomplete.Count -eq 0 -and $nonInteractive -ne $false)
        ReadCount              = $readCount
        NonInteractiveAssessed = $nonInteractive
        FallbackReason         = $fallbackReason
    }
}
