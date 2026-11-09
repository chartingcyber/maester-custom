function Find-ResSignInHunting {
    <#
    .SYNOPSIS
    Finds the first few successful sign-ins that are a finding, with one Defender advanced hunting query.

    .DESCRIPTION
    Runs KQL against the advanced hunting table EntraIdSignInEvents (interactive and non-interactive sign-ins,
    kept for 30 days) through Invoke-MtGraphSecurityQuery (Graph security/runHuntingQuery). It is one request that
    returns in seconds, where the Graph sign-in log takes about 40 seconds per request. The table needs Microsoft
    Entra ID P2 and access to Defender advanced hunting.

    Kind Country: successful sign-ins whose country is known and is not in ExpectedCountry.
    Kind Legacy: successful sign-ins whose client app is named and is not Browser, Mobile Apps and Desktop
    clients, or Unknown.

    A first query counts the successful sign-ins in the period, so that an empty table is not mistaken for a
    clean result. Throws when the query fails (no licence, no access, table missing, a bad query): the caller
    decides what to tell the user. Matches use the property names of the Graph sign-in log (userPrincipalName,
    createdDateTime, location.countryOrRegion, appDisplayName, ipAddress, clientAppUsed) plus logonType.

    Returns Matches (at most MaximumMatches), AtLeast (true when the limit was reached), Total (successful
    sign-ins in the period), Oldest (the oldest of them) and Query.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Country', 'Legacy')]
        [string] $Kind,

        # Two-letter country codes that are expected. Used by Kind Country.
        [ValidatePattern('^[A-Za-z]{2}$')]
        [string[]] $ExpectedCountry = @(),

        # How many days to search. Advanced hunting keeps 30 days.
        [ValidateRange(1, 30)]
        [int] $LookbackDays = 7,

        # Return at most this many matching sign-ins.
        [ValidateRange(1, 50)]
        [int] $MaximumMatches = 10
    )

    $span = "P$($LookbackDays)D"
    $base = "EntraIdSignInEvents | where Timestamp > ago($($LookbackDays)d) | where ErrorCode == 0"

    $summary = @(Invoke-MtGraphSecurityQuery -Query "$base | summarize Total = count(), Oldest = min(Timestamp)" -Timespan $span)
    $total = if ($summary.Count -gt 0 -and $null -ne $summary[0].Total) { [long]$summary[0].Total } else { 0 }
    $oldest = if ($summary.Count -gt 0) { $summary[0].Oldest } else { $null }

    $filter = if ($Kind -eq 'Country') {
        $codes = @($ExpectedCountry | ForEach-Object { ([string]$_).Trim().ToUpperInvariant() } | Where-Object { $_ } | ForEach-Object { '"' + $_ + '"' })
        if ($codes.Count -eq 0) { throw 'ExpectedCountry needs at least one two-letter country code.' }
        "| where isnotempty(Country) and Country !in~ ($($codes -join ', '))"
    } else {
        '| where isnotempty(ClientAppUsed) and ClientAppUsed !in~ ("Browser", "Mobile Apps and Desktop clients", "Unknown")'
    }
    $query = "$base $filter | project Timestamp, AccountUpn, Country, City, Application, ClientAppUsed, LogonType, IPAddress | order by Timestamp desc | take $MaximumMatches"

    $rows = @(Invoke-MtGraphSecurityQuery -Query $query -Timespan $span)
    $hits = @($rows | ForEach-Object {
            [pscustomobject]@{
                userPrincipalName = [string]$_.AccountUpn
                createdDateTime   = $_.Timestamp
                location          = [pscustomobject]@{ countryOrRegion = [string]$_.Country; city = [string]$_.City }
                appDisplayName    = [string]$_.Application
                clientAppUsed     = [string]$_.ClientAppUsed
                logonType         = [string]$_.LogonType
                ipAddress         = [string]$_.IPAddress
            }
        })

    [pscustomobject]@{
        Matches = $hits
        AtLeast = ($hits.Count -ge $MaximumMatches)
        Total   = $total
        Oldest  = $oldest
        Query   = $query
    }
}
