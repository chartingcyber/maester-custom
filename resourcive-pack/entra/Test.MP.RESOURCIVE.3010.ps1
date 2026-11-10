function Test-ResPrivilegedRoleInventory {
    <#
    .SYNOPSIS
    Lists every user who holds a privileged Entra directory role, with the roles each one holds.

    .DESCRIPTION
    Reads the active role assignments and, when the tenant has Entra ID P2 or Governance, the eligible (PIM)
    assignments of the roles Microsoft marks as privileged. Role-assignable groups are expanded to their user
    members. The result is an inventory for a person to review, so it never fails: it is Investigate when anyone
    holds a role. Each row is marked when the account is a guest, disabled, synced from on-premises Active Directory,
    or holds many roles, because those are the accounts that most often should not be privileged. Service principals
    that hold roles are not listed.
    #>
    [MaesterTest(
        Id           = 'MP.RESOURCIVE.3010',
        Title        = 'Every account that holds a privileged role is listed for review.',
        Product      = 'entra',
        Feature      = 'roles',
        Area         = 'privileged-access',
        ResourceType = 'User',
        Severity     = 'Info',
        Mitre        = 'None',
        Service      = 'Graph',
        Permission   = ('Graph:Scope:RoleManagement.Read.Directory', 'Graph:Scope:Directory.Read.All')
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

    if ($privileged.Count -eq 0) {
        Add-MtTestResultDetail -Result 'No user holds a privileged role in this tenant.'
        return $true
    }

    $rows = foreach ($user in ($privileged | Sort-Object { -@($_.Roles).Count }, UserPrincipalName)) {
        $marks = [System.Collections.Generic.List[string]]::new()
        if ($user.UserType -eq 'Guest') { $marks.Add('Guest') }
        if ($user.AccountEnabled -eq $false) { $marks.Add('Disabled') }
        if ($user.OnPremisesSyncEnabled) { $marks.Add('Synced from on-premises') }
        if (@($user.Roles).Count -ge $ManyRoles) { $marks.Add("$(@($user.Roles).Count) roles") }
        [pscustomobject]@{
            User     = $user.UserPrincipalName
            Type     = if ($user.UserType) { $user.UserType } else { 'Member' }
            Enabled  = if ($user.AccountEnabled -eq $false) { 'No' } else { 'Yes' }
            Source   = if ($user.OnPremisesSyncEnabled) { 'Synced' } else { 'Cloud' }
            Active   = (@($user.ActiveRoles) -join ', ')
            Eligible = (@($user.EligibleRoles) -join ', ')
            Review   = ($marks -join '; ')
        }
    }
    $rows = @($rows)

    $byRole = foreach ($role in (@($privileged | ForEach-Object { $_.Roles }) | Select-Object -Unique)) {
        $holders = @($privileged | Where-Object { $role -in $_.Roles })
        [pscustomobject]@{
            Role     = $role
            Holders  = $holders.Count
            Active   = @($holders | Where-Object { $role -in $_.ActiveRoles }).Count
            Eligible = @($holders | Where-Object { $role -in $_.EligibleRoles }).Count
        }
    }
    $byRole = @($byRole | Sort-Object Holders -Descending)

    $flagged = @($rows | Where-Object { $_.Review })
    $summary = "$($rows.Count) account(s) hold a privileged role, as of $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm')) UTC. $($flagged.Count) are marked for review (guest, disabled, synced from on-premises, or $ManyRoles or more roles)."
    $note = Get-ResPrivilegedUserNote -User $privileged

    $roleTable = "| Role | Holders | Active | Eligible |`n| --- | --- | --- | --- |`n" +
        (($byRole | ForEach-Object { "| $($_.Role) | $($_.Holders) | $($_.Active) | $($_.Eligible) |" }) -join "`n")
    $userTable = "| User | Type | Enabled | Source | Active roles | Eligible roles | Review |`n| --- | --- | --- | --- | --- | --- | --- |`n" +
        (($rows | Select-Object -First $MaximumRows | ForEach-Object { "| $($_.User) | $($_.Type) | $($_.Enabled) | $($_.Source) | $($_.Active) | $($_.Eligible) | $($_.Review) |" }) -join "`n")
    $more = if ($rows.Count -gt $MaximumRows) { "`n`nShowing the first $MaximumRows of $($rows.Count) accounts." } else { '' }

    Add-MtTestResultDetail -Result "$summary$note`n`n**Holders by role**`n`n$roleTable`n`n**Accounts**`n`n$userTable$more" -Investigate
    return $true
}
