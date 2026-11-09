function Test-ResBroadApplicationPermissions {
    <#
    .SYNOPSIS
    Checks for third-party and owner-less applications that hold broad Microsoft Graph application permissions.

    .DESCRIPTION
    Reads the service principals in the tenant that are not Microsoft's own, and the Microsoft Graph application
    permissions granted to each. An application is flagged when it holds one of the RiskyPermissions and either is
    owned by another organization (a multi-tenant app) or has no owner in this tenant. Application permissions work
    without a signed-in user, so a broad one on an app nobody owns is a persistent, silent path to your data.
    MT.1050 and MT.1051 look for paths to Global Administrator; MT.1057 and MT.1199 look at credentials. This check
    looks at the breadth of the permissions and who owns the app.
    #>
    [MaesterTest(
        Id           = 'MP.RESOURCIVE.3008',
        Title        = 'No third-party or owner-less application holds broad Microsoft Graph application permissions.',
        Product      = 'entra',
        Feature      = 'app-consent',
        Area         = 'applications',
        ResourceType = 'ServicePrincipal',
        Severity     = 'High',
        UserImpact   = 'Medium',
        ImplementationCost = 'Medium',
        Mitre        = ('T1098.003', 'T1528', 'T1114.002'),
        Control      = ('nist-800-53-r5:AC-6', 'nist-800-53-r5:CM-7'),
        Service      = 'Graph',
        Permission   = ('Graph:Scope:Application.Read.All', 'Graph:Scope:Directory.Read.All'),
        LongRunning
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        # Microsoft Graph application permissions that can change or take over data. A third-party or owner-less
        # application with one of these fails the check.
        [string[]] $RiskyPermissions = @(
            'Directory.ReadWrite.All', 'RoleManagement.ReadWrite.Directory', 'Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All',
            'Mail.ReadWrite', 'Mail.Send', 'MailboxSettings.ReadWrite', 'Files.ReadWrite.All', 'Sites.FullControl.All',
            'Sites.ReadWrite.All', 'User.ReadWrite.All', 'Group.ReadWrite.All', 'Policy.ReadWrite.ConditionalAccess', 'Calendars.ReadWrite'
        ),

        # Broad read permissions. Many legitimate products hold them, so they are listed for review and do not fail
        # the check by themselves.
        [string[]] $BroadReadPermissions = @('Mail.Read', 'User.Read.All', 'Directory.Read.All', 'Chat.Read.All'),

        # The most service principals to inspect.
        [ValidateRange(1, 20000)]
        [int] $MaximumApplications = 2000
    )

    $microsoftTenantId = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a'
    $graphAppId = '00000003-0000-0000-c000-000000000000'

    try {
        $organization = @(Invoke-MtGraphRequest -RelativeUri 'organization' -ApiVersion v1.0 -Select id -ErrorAction Stop)[0]
        $graphSp = @(Invoke-MtGraphRequest -RelativeUri 'servicePrincipals' -ApiVersion v1.0 -Filter "appId eq '$graphAppId'" -Select id, appRoles -ErrorAction Stop)[0]
        $servicePrincipals = @(Invoke-MtGraphRequest -RelativeUri 'servicePrincipals' -ApiVersion v1.0 -Filter "servicePrincipalType eq 'Application'" -Select id, displayName, appId, appOwnerOrganizationId -ErrorAction Stop)
    } catch {
        Resolve-ResGraphError -ErrorRecord $_ -Feature 'service principals' -Requires 'Application.Read.All and Directory.Read.All'
    }

    $roleName = @{}
    foreach ($role in @($graphSp.appRoles)) { $roleName[[string]$role.id] = [string]$role.value }

    $candidates = @($servicePrincipals | Where-Object { $_.appOwnerOrganizationId -ne $microsoftTenantId } | Select-Object -First $MaximumApplications)
    $unreadable = [System.Collections.Generic.List[string]]::new()
    $findings = foreach ($sp in $candidates) {
        try {
            $assignments = @(Invoke-MtGraphRequest -RelativeUri "servicePrincipals/$($sp.id)/appRoleAssignments" -ApiVersion v1.0 -ErrorAction Stop | Where-Object { $_.resourceId -eq $graphSp.id })
        } catch {
            $unreadable.Add([string]$sp.displayName)
            continue
        }
        $granted = @($assignments | ForEach-Object { $roleName[[string]$_.appRoleId] } | Where-Object { $_ })
        $risky = @($granted | Where-Object { $_ -in $RiskyPermissions })
        $broad = @($granted | Where-Object { $_ -in $BroadReadPermissions })
        if ($risky.Count -eq 0 -and $broad.Count -eq 0) { continue }
        $external = $sp.appOwnerOrganizationId -and $sp.appOwnerOrganizationId -ne $organization.id
        $owner = if ($external) { "external tenant $($sp.appOwnerOrganizationId)" } else {
            try {
                $owners = @(Invoke-MtGraphRequest -RelativeUri "servicePrincipals/$($sp.id)/owners" -ApiVersion v1.0 -ErrorAction Stop)
                if ($owners.Count -gt 0) { $null } else { 'this tenant, no owner' }
            } catch { 'this tenant, owner could not be read' }
        }
        # An application of this tenant that has an owner is accountable; only external or owner-less ones are listed.
        if (-not $owner) { continue }
        [pscustomobject]@{
            Application = [string]$sp.displayName
            Owner       = $owner
            Risky       = (($risky | Select-Object -Unique) -join ', ')
            BroadRead   = (($broad | Select-Object -Unique) -join ', ')
        }
    }
    $findings = @($findings | Where-Object { $null -ne $_ })
    $failing = @($findings | Where-Object { $_.Risky })
    $readOnly = @($findings | Where-Object { -not $_.Risky })

    $asOf = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm')
    $scope = "Inspected $($candidates.Count) non-Microsoft service principals as of $asOf UTC.$(if ($servicePrincipals.Count -gt $MaximumApplications) { ' The list was limited, so some applications are not assessed.' })$(if ($unreadable.Count -gt 0) { " The permissions of $($unreadable.Count) application(s) could not be read, so they are not assessed." })"

    function Get-FindingTable {
        param($Finding, [string] $Column)
        "| Application | Owned by | Permissions |`n| --- | --- | --- |`n" + ((@($Finding) | Select-Object -First 100 | ForEach-Object { "| $($_.Application) | $($_.Owner) | $($_.$Column) |" }) -join "`n")
    }
    $readText = if ($readOnly.Count -gt 0) { "`n`n**$($readOnly.Count) application(s) hold only broad read permissions** (for review, not a failure by themselves):`n`n$(Get-FindingTable $readOnly 'BroadRead')" } else { '' }

    if ($failing.Count -eq 0) {
        if ($readOnly.Count -gt 0) {
            Add-MtTestResultDetail -Result "No third-party or owner-less application holds a high-impact Graph application permission. $scope$readText" -Investigate
            return $false
        }
        Add-MtTestResultDetail -Result "Well done. No third-party or owner-less application holds the listed broad Graph application permissions. $scope"
        return $true
    }
    Add-MtTestResultDetail -Result "$($failing.Count) third-party or owner-less application(s) hold high-impact Graph application permissions. $scope`n`n$(Get-FindingTable $failing 'Risky')$readText"
    return $false
}
