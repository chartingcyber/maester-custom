function Test-ResSecurityChangeLog {
    <#
    .SYNOPSIS
    Lists the changes to Conditional Access, directory roles, authentication methods and cross-tenant settings recorded in the Entra audit log, for review.

    .DESCRIPTION
    Reads the Entra directory audit log for successful changes in the last LookbackDays days in these categories:
    policy changes (Conditional Access, authentication methods, cross-tenant access, authorization policy), role
    assignment changes, and application consent. The result lists who changed what and when. This is an information
    check: it never fails, and the result is Investigate whenever there are changes to review.

    Entra keeps audit logs for 7 days on the Free tier and 30 days with Entra ID P1 or P2, so the lookback is limited to
    that. Longer history needs the unified audit log (Microsoft Purview), which this check does not read.
    #>
    [MaesterTest(
        Id           = 'MP.RESOURCIVE.3001',
        Title        = 'Recent changes to Conditional Access, roles and authentication settings are listed for review.',
        Product      = 'entra',
        Feature      = 'monitoring',
        Area         = 'logging-and-detection',
        ResourceType = 'Tenant',
        Severity     = 'Info',
        Mitre        = 'None',
        Service      = 'Graph',
        Permission   = 'Graph:Scope:AuditLog.Read.All'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        # How many days of audit log to read. Entra keeps 7 days (Free) or 30 days (P1 or P2).
        [ValidateRange(1, 30)]
        [int] $LookbackDays = 30,

        # The most changes to list in the result.
        [ValidateRange(1, 1000)]
        [int] $MaximumListed = 100
    )

    $since = (Get-Date).ToUniversalTime().AddDays(-$LookbackDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $filter = "activityDateTime ge $since and result eq 'success' and (category eq 'Policy' or category eq 'RoleManagement' or category eq 'ApplicationManagement')"

    try {
        $events = @(Invoke-MtGraphRequest -RelativeUri 'auditLogs/directoryAudits' -ApiVersion v1.0 -Filter $filter -ErrorAction Stop)
    } catch {
        Resolve-ResGraphError -ErrorRecord $_ -Feature 'the Entra audit log' -Requires 'AuditLog.Read.All and Reports Reader, Security Reader or Global Reader'
    }

    $interesting = @($events | Where-Object {
            $_.activityDisplayName -match 'conditional access|authentication method|cross-tenant|authorization policy|role assignment|add member to role|remove member from role|eligible|consent|permission grant|add app role|certificates and secrets|Update application' -or
            $_.category -eq 'RoleManagement'
        })

    $asOf = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm')
    if ($interesting.Count -eq 0) {
        Add-MtTestResultDetail -Result "No policy, role or consent changes were recorded in the last $LookbackDays days (as of $asOf UTC). Entra keeps this log for 7 days (Free) or 30 days (P1 or P2), so older changes are not visible here."
        return $true
    }

    $rows = @($interesting | Sort-Object activityDateTime -Descending | Select-Object -First $MaximumListed | ForEach-Object {
            $actor = if ($_.initiatedBy.user.userPrincipalName) { $_.initiatedBy.user.userPrincipalName } elseif ($_.initiatedBy.app.displayName) { "app: $($_.initiatedBy.app.displayName)" } else { 'unknown' }
            $target = (@($_.targetResources | ForEach-Object { $_.displayName } | Where-Object { $_ }) -join ', ')
            "| $($_.activityDateTime) | $($_.activityDisplayName) | $actor | $target |"
        })
    $table = "| When (UTC) | Change | By | Target |`n| --- | --- | --- | --- |`n" + ($rows -join "`n")
    $more = if ($interesting.Count -gt $MaximumListed) { "`n`nThe latest $MaximumListed of $($interesting.Count) changes are shown." } else { '' }
    Add-MtTestResultDetail -Result "$($interesting.Count) security-relevant change(s) in the last $LookbackDays days (as of $asOf UTC). Confirm each was planned.`n`n$table$more" -Investigate
    return $true
}
