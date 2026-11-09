function Test-ResLegacyAuthenticationSignIns {
    <#
    .SYNOPSIS
    Checks the sign-in log for successful sign-ins that used a legacy authentication protocol in the last few days.

    .DESCRIPTION
    Legacy protocols (IMAP, POP, SMTP AUTH, Exchange ActiveSync with basic authentication, and the other
    "other clients") cannot do MFA, so a password is enough. A Conditional Access policy that blocks them is checked by
    MT.1009, MT.1010 and CISA MS.AAD.1.1 and simulated by MT.1033. This check looks at what actually happened: it reads
    the successful sign-ins whose client app is not a browser and not a modern mobile or desktop client, and lists the
    users and protocols. Any such sign-in fails the check.

    The sign-in log is slow and one request for many days can time out, so the check reads one small request per day,
    newest first, until it has read every day or used its time budget, filters by client app in PowerShell, and states
    which days were read and which only in part. A result of no legacy sign-ins is therefore only a pass when every day
    was read in full; otherwise it is Investigate.

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
        Permission   = 'Graph:Scope:AuditLog.Read.All'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        # How many days of sign-ins to try to read, newest first. Entra keeps 30 days.
        [ValidateRange(1, 30)]
        [int] $LookbackDays = 7,

        # The most sign-in records to read for each day, in one request. The newest records of the day are read first.
        [ValidateRange(50, 1000)]
        [int] $MaximumSignInsPerDay = 200,

        # Stop starting new days after this many seconds. A request already running is not interrupted.
        [ValidateRange(30, 1800)]
        [int] $TimeBudgetSeconds = 240,

        # The most users to list in the result.
        [ValidateRange(1, 500)]
        [int] $MaximumListed = 50
    )

    Assert-ResLicense -Name 'Microsoft Entra ID P1' -ServicePlan (Get-ResServicePlanName -Product EntraP1)

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
            $page = Get-ResGraphPage (Invoke-MtGraphRequest -RelativeUri 'auditLogs/signIns' -ApiVersion v1.0 -Filter "createdDateTime ge $from and createdDateTime lt $to" -Select userPrincipalName, clientAppUsed, createdDateTime, appDisplayName, ipAddress, status -QueryParameters @{ '$top' = $MaximumSignInsPerDay } -DisablePaging -ErrorAction Stop)
            $rows = @($page.Rows)
        } catch {
            if ([string]$_.Exception.Message -match 'Timeout|timed out|canceled') {
                $days.Add([pscustomobject]@{ Day = $label; State = 'Not read (request timed out)'; Rows = 0 })
                continue
            }
            Resolve-ResGraphError -ErrorRecord $_ -Feature 'the sign-in log' -Requires 'AuditLog.Read.All and Reports Reader, Security Reader or Global Reader'
        }
        foreach ($row in $rows) { $signIns.Add($row) }
        $state = if ($page.HasMore -or $rows.Count -ge $MaximumSignInsPerDay) { "Partly read (newest $MaximumSignInsPerDay of the day)" } else { 'Read' }
        $days.Add([pscustomobject]@{ Day = $label; State = $state; Rows = $rows.Count })
    }

    $unread = @($days | Where-Object { $_.State -like 'Not read*' })
    $partial = @($days | Where-Object { $_.State -like 'Partly*' })
    if ($unread.Count -eq $days.Count) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason "Not assessed: no day of the sign-in log could be read within the time budget of $TimeBudgetSeconds seconds, or the requests timed out."
    }
    $daysTable = "| Day (UTC) | Coverage | Records read |`n| --- | --- | --- |`n" + ((@($days) | ForEach-Object { "| $($_.Day) | $($_.State) | $($_.Rows) |" }) -join "`n")

    # A sign-in is legacy when it succeeded and its client app is named and is not a modern client. 'Unknown' means the log did not record the client.
    $legacy = @($signIns | Where-Object { $_.status -and $_.status.errorCode -eq 0 -and $_.clientAppUsed -and $_.clientAppUsed -notin @('Browser', 'Mobile Apps and Desktop clients', 'Unknown') })

    $asOf = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm')
    $coverage = if ($unread.Count -gt 0 -or $partial.Count -gt 0) { " Coverage is incomplete: $($unread.Count) of $($days.Count) day(s) were not read and $($partial.Count) were only partly read, so legacy sign-ins outside the records read are not assessed." } else { '' }
    $scope = "Read $($signIns.Count) sign-in records from the last $LookbackDays days as of $asOf UTC.$coverage"

    if ($legacy.Count -eq 0) {
        if ($coverage) {
            Add-MtTestResultDetail -Result "No legacy sign-in found in the records read, but this is not a pass. $scope Check the sign-in log in the Entra admin center filtered by Client app, or raise MaximumSignInsPerDay or TimeBudgetSeconds.`n`n$daysTable" -Investigate
            return $false
        }
        Add-MtTestResultDetail -Result "Well done. No successful sign-in used a legacy authentication protocol. $scope`n`n$daysTable"
        return $true
    }

    $byProtocol = $legacy | Group-Object clientAppUsed | Sort-Object Count -Descending
    $byUser = $legacy | Group-Object userPrincipalName | Sort-Object Count -Descending | Select-Object -First $MaximumListed
    $protocolTable = "| Protocol | Successful sign-ins |`n| --- | --- |`n" + ((@($byProtocol) | ForEach-Object { "| $($_.Name) | $($_.Count) |" }) -join "`n")
    $userTable = "| User | Sign-ins | Protocols | Last seen |`n| --- | --- | --- | --- |`n" + ((@($byUser) | ForEach-Object {
                $last = ($_.Group | Sort-Object createdDateTime -Descending | Select-Object -First 1).createdDateTime
                "| $($_.Name) | $($_.Count) | $((@($_.Group | ForEach-Object { $_.clientAppUsed } | Select-Object -Unique)) -join ', ') | $last |"
            }) -join "`n")
    Add-MtTestResultDetail -Result "$($legacy.Count) successful sign-in(s) by $(@($legacy | Select-Object -ExpandProperty userPrincipalName -Unique).Count) user(s) used a legacy protocol. $scope`n`n$protocolTable`n`n$userTable`n`n$daysTable"
    return $false
}
