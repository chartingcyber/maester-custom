function Test-ResLegacyAuthenticationSignIns {
    <#
    .SYNOPSIS
    Checks the sign-in log for successful sign-ins that used a legacy authentication protocol in the last few days.

    .DESCRIPTION
    Legacy protocols (IMAP, POP, SMTP AUTH, Exchange ActiveSync with basic authentication, and the other
    "other clients") cannot do MFA, so a password is enough. A Conditional Access policy that blocks them is checked by
    MT.1009, MT.1010 and CISA MS.AAD.1.1 and simulated by MT.1033. This check looks at what actually happened: it
    searches the Defender advanced hunting table EntraIdSignInEvents (interactive and non-interactive sign-ins) for
    successful sign-ins whose client app is not a browser and not a modern mobile or desktop client, and stops at
    the first MaximumMatches (default 10). Any match fails the check. Legacy protocols usually sign in
    non-interactively, which the Graph v1.0 sign-in log does not return, so the hunting table is what makes this
    check possible.

    The table needs Microsoft Entra ID P2 and access to Defender advanced hunting. When the tenant has no P2, or
    the query cannot run, or it finds no sign-ins at all, the result is Investigate with the reason and the steps
    to do the same check in the Microsoft Entra admin center. It is never a pass in those cases.
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
        Permission   = 'Graph:Scope:ThreatHunting.Read.All'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        # How many days of sign-ins to search. Advanced hunting keeps 30 days.
        [ValidateRange(1, 30)]
        [int] $LookbackDays = 7,

        # Stop after this many legacy sign-ins.
        [ValidateRange(1, 50)]
        [int] $MaximumMatches = 10
    )

    $reason = $null
    $found = $null
    if ((Test-ResLicense -ServicePlan (Get-ResServicePlanName -Product EntraP2)) -eq $false) {
        $reason = 'the tenant does not have Microsoft Entra ID P2, which the advanced hunting sign-in table needs.'
    } else {
        try {
            $found = Find-ResSignInHunting -Kind Legacy -LookbackDays $LookbackDays -MaximumMatches $MaximumMatches
        } catch {
            $reason = "the advanced hunting query could not run ($((([string]$_.Exception.Message) -split "`n")[0].Trim())). It needs Entra ID P2, the ThreatHunting.Read.All permission and a role with Defender advanced hunting access, such as Security Reader."
        }
        if (-not $reason -and $found.Total -eq 0) {
            $reason = "the advanced hunting table returned no successful sign-ins for the last $LookbackDays days, so it cannot confirm that none used a legacy protocol."
        }
    }
    if ($reason) {
        Add-MtTestResultDetail -Result (Get-ResSignInManualCheck -Kind Legacy -Reason $reason -LookbackDays $LookbackDays) -Investigate
        return $false
    }

    $asOf = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm')
    $how = "Searched $($found.Total) successful sign-ins from the last $LookbackDays days (interactive and non-interactive, oldest $($found.Oldest)) with Defender advanced hunting (EntraIdSignInEvents)."

    if ($found.Matches.Count -eq 0) {
        Add-MtTestResultDetail -Result "Well done. No successful sign-in used a legacy authentication protocol, as of $asOf UTC. $how"
        return $true
    }

    $limit = if ($found.AtLeast) { "At least $($found.Matches.Count) (the search stops at $MaximumMatches)" } else { "$($found.Matches.Count)" }
    $table = "| When (UTC) | User | Protocol | App | Logon type | IP address |`n| --- | --- | --- | --- | --- | --- |`n" + ((@($found.Matches) | ForEach-Object { "| $($_.createdDateTime) | $($_.userPrincipalName) | $($_.clientAppUsed) | $($_.appDisplayName) | $($_.logonType) | $($_.ipAddress) |" }) -join "`n")
    Add-MtTestResultDetail -Result "$limit successful sign-in(s) used a legacy authentication protocol in the last $LookbackDays days, as of $asOf UTC. $how`n`n$table"
    return $false
}
