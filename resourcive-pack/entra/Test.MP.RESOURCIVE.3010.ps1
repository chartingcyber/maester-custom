function Test-ResPrivilegedRoleInventory {
    <#
    .SYNOPSIS
    Lists every user, application and managed identity that holds a privileged Entra directory role, with the roles each one holds.

    .DESCRIPTION
    Reads the active role assignments and, when the tenant has Entra ID P2 or Governance, the eligible (PIM)
    assignments of the roles Microsoft marks as privileged. Role-assignable groups are expanded to their user
    members. The result is an inventory for a person to review, so it never fails: it is Investigate when anyone
    holds a role. Each row is marked when the account is a guest, disabled, synced from on-premises Active Directory,
    or holds many roles, or cannot complete multifactor authentication, because those are the accounts that most often should not be privileged.
    Applications and managed identities are listed in a second table with who owns them and whether they have client secrets or certificates.
    #>
    [MaesterTest(
        Id           = 'MP.RESOURCIVE.3010',
        Title        = 'Every user, application and managed identity that holds a privileged role is listed for review.',
        Product      = 'entra',
        Feature      = 'roles',
        Area         = 'privileged-access',
        ResourceType = 'User',
        Severity     = 'Info',
        Mitre        = 'None',
        Service      = 'Graph',
        Permission   = ('Graph:Scope:RoleManagement.Read.Directory', 'Graph:Scope:Directory.Read.All', 'Graph:Scope:AuditLog.Read.All', 'Graph:Scope:Application.Read.All')
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        # An account holding this many roles or more is marked for review.
        [ValidateRange(2, 50)]
        [int] $ManyRoles = 3,

        # The most accounts to list. The totals always count every account.
        [ValidateRange(10, 1000)]
        [int] $MaximumRows = 200
    )

    try {
        $privileged = @(Get-ResPrivilegedUser)
    } catch {
        Resolve-ResGraphError -ErrorRecord $_ -Feature 'privileged role assignments' -Requires 'RoleManagement.Read.Directory and Directory.Read.All'
    }

    # Applications and managed identities that hold a role. A failure here must not hide the user inventory.
    $apps = @()
    $appNote = ''
    try {
        $apps = @(Get-ResPrivilegedServicePrincipal)
    } catch {
        $appNote = ' Applications and managed identities that hold a role could not be read (it needs the Application.Read.All permission).'
    }

    if ($privileged.Count -eq 0 -and $apps.Count -eq 0) {
        Add-MtTestResultDetail -Result 'No user, application or managed identity holds a privileged role in this tenant.'
        return $true
    }

    # MFA capability needs Entra ID P1 and AuditLog.Read.All. Without them the column says Unknown; it is never a guess.
    $registrations = @{}
    $mfaNote = ''
    try {
        foreach ($registration in @(Invoke-MtGraphRequest -RelativeUri 'reports/authenticationMethods/userRegistrationDetails' -ApiVersion v1.0 -ErrorAction Stop)) { $registrations[[string]$registration.id] = $registration }
    } catch {
        $mfaNote = ' MFA capability could not be read (it needs Entra ID P1 and the AuditLog.Read.All permission), so the MFA column shows Unknown.'
    }

    $rows = foreach ($user in ($privileged | Sort-Object { -@($_.Roles).Count }, UserPrincipalName)) {
        $marks = [System.Collections.Generic.List[string]]::new()
        if ($user.UserType -eq 'Guest') { $marks.Add('Guest') }
        if ($user.AccountEnabled -eq $false) { $marks.Add('Disabled') }
        if ($user.OnPremisesSyncEnabled) { $marks.Add('Synced from on-premises') }
        if (@($user.Roles).Count -ge $ManyRoles) { $marks.Add("$(@($user.Roles).Count) roles") }
        $registration = $registrations[[string]$user.Id]
        $mfa = if (-not $registration) { 'Unknown' } elseif ($registration.isMfaCapable) { 'Capable' } else { 'Not capable' }
        if ($mfa -eq 'Not capable' -and $user.AccountEnabled -ne $false) { $marks.Add('No MFA') }
        [pscustomobject]@{
            User     = $user.UserPrincipalName
            Type     = if ($user.UserType) { $user.UserType } else { 'Member' }
            Enabled  = if ($user.AccountEnabled -eq $false) { 'No' } else { 'Yes' }
            Source   = if ($user.OnPremisesSyncEnabled) { 'Synced' } else { 'Cloud' }
            Mfa      = $mfa
            Active   = (@($user.ActiveRoles) -join ', ')
            Eligible = (@($user.EligibleRoles) -join ', ')
            Review   = ($marks -join '; ')
        }
    }
    $rows = @($rows)

    $byRole = foreach ($role in (@(@($privileged | ForEach-Object { $_.Roles }) + @($apps | ForEach-Object { $_.Roles })) | Select-Object -Unique)) {
        $holders = @($privileged | Where-Object { $role -in $_.Roles })
        [pscustomobject]@{
            Role         = $role
            Holders      = $holders.Count
            Active       = @($holders | Where-Object { $role -in $_.ActiveRoles }).Count
            Eligible     = @($holders | Where-Object { $role -in $_.EligibleRoles }).Count
            Applications = @($apps | Where-Object { $role -in $_.Roles }).Count
        }
    }
    $byRole = @($byRole | Sort-Object Holders -Descending)

    $appRows = foreach ($app in ($apps | Sort-Object DisplayName)) {
        $marks = [System.Collections.Generic.List[string]]::new()
        if ($app.IsThirdParty) { $marks.Add('Third-party application') }
        if ($app.SecretCount -gt 0) { $marks.Add("$($app.SecretCount) client secret(s)") }
        if ($app.AccountEnabled -eq $false) { $marks.Add('Disabled') }
        if (@($app.Roles).Count -ge $ManyRoles) { $marks.Add("$(@($app.Roles).Count) roles") }
        [pscustomobject]@{
            Application = $app.DisplayName
            Type        = if ($app.Type -eq 'ManagedIdentity') { 'Managed identity' } else { 'Application' }
            Owner       = if ($app.IsThirdParty) { 'Another organization' } elseif ($app.OwnerOrganizationId) { 'This tenant or Microsoft' } else { 'Unknown' }
            Secrets     = if ($null -eq $app.SecretCount) { 'Unknown' } else { $app.SecretCount }
            Certificates = if ($null -eq $app.CertificateCount) { 'Unknown' } else { $app.CertificateCount }
            Active      = (@($app.ActiveRoles) -join ', ')
            Eligible    = (@($app.EligibleRoles) -join ', ')
            Review      = ($marks -join '; ')
        }
    }
    $appRows = @($appRows)
    $flagged = @($rows | Where-Object { $_.Review })
    $appFlagged = @($appRows | Where-Object { $_.Review })
    $appSentence = if ($appRows.Count -gt 0) { " $($appRows.Count) application(s) or managed identity(ies) also hold a privileged role, $($appFlagged.Count) marked for review (third-party, client secret, disabled or many roles)." } else { '' }
    $summary = "$($rows.Count) account(s) hold a privileged role, as of $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm')) UTC. $($flagged.Count) are marked for review (guest, disabled, synced from on-premises, not MFA capable, or $ManyRoles or more roles).$appSentence"
    $note = (Get-ResPrivilegedUserNote -User $privileged) + $mfaNote + $appNote

    $roleTable = "| Role | Holders | Active | Eligible | Applications |`n| --- | --- | --- | --- | --- |`n" +
        (($byRole | ForEach-Object { "| $($_.Role) | $($_.Holders) | $($_.Active) | $($_.Eligible) | $($_.Applications) |" }) -join "`n")
    $userTable = "| User | Type | Enabled | Source | MFA | Active roles | Eligible roles | Review |`n| --- | --- | --- | --- | --- | --- | --- | --- |`n" +
        (($rows | Select-Object -First $MaximumRows | ForEach-Object { "| $($_.User) | $($_.Type) | $($_.Enabled) | $($_.Source) | $($_.Mfa) | $($_.Active) | $($_.Eligible) | $($_.Review) |" }) -join "`n")
    $more = if ($rows.Count -gt $MaximumRows) { "`n`nShowing the first $MaximumRows of $($rows.Count) accounts." } else { '' }

    $appTable = if ($appRows.Count -gt 0) {
        "`n`n**Applications and managed identities**`n`n| Application | Type | Owner | Secrets | Certificates | Active roles | Eligible roles | Review |`n| --- | --- | --- | --- | --- | --- | --- | --- |`n" +
        (($appRows | ForEach-Object { "| $($_.Application) | $($_.Type) | $($_.Owner) | $($_.Secrets) | $($_.Certificates) | $($_.Active) | $($_.Eligible) | $($_.Review) |" }) -join "`n")
    } else { '' }

    Add-MtTestResultDetail -Result "$summary$note`n`n**Holders by role**`n`n$roleTable`n`n**Accounts**`n`n$userTable$more$appTable" -Investigate
    return $true
}
