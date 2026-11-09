function Get-ResPrivilegedUser {
    <#
    .SYNOPSIS
    Returns every user who holds a privileged Entra directory role, active or eligible, with the roles held.

    .DESCRIPTION
    Reads role definitions flagged isPrivileged, then the active role assignments and, when the tenant has Entra
    ID P2 or Governance, the eligible assignments. Role-assignable groups are expanded to their user members.
    Service principals are left out. Eligible assignments are skipped without an error when the tenant has no
    PIM licence, and the result says so in the Eligible note.

    Returns one object per user: Id, UserPrincipalName, DisplayName, Mail, AccountEnabled, UserType,
    OnPremisesSyncEnabled, Roles (names), ActiveRoles, EligibleRoles, and a property EligibleReadable that is
    $false when eligible assignments could not be read.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        # Leave eligible (PIM) assignments out.
        [switch] $ActiveOnly
    )

    # isPrivileged is returned only by the beta endpoint; v1.0 leaves it out, which would make every role look unprivileged.
    $definitions = @(Invoke-MtGraphRequest -RelativeUri 'roleManagement/directory/roleDefinitions' -ApiVersion beta)
    $privileged = @{}
    foreach ($definition in $definitions) {
        if ($definition.isPrivileged) { $privileged[[string]$definition.id] = [string]$definition.displayName }
    }

    $users = @{}
    $eligibleReadable = $true

    function Add-RoleMember {
        param($Principal, $RoleName, $Kind)
        if ($Principal.'@odata.type' -ne '#microsoft.graph.user') { return }
        $id = [string]$Principal.id
        if (-not $users.ContainsKey($id)) {
            $users[$id] = [pscustomobject]@{
                Id                    = $id
                UserPrincipalName     = [string]$Principal.userPrincipalName
                DisplayName           = [string]$Principal.displayName
                Mail                  = [string]$Principal.mail
                AccountEnabled        = $Principal.accountEnabled
                UserType              = [string]$Principal.userType
                OnPremisesSyncEnabled = [bool]$Principal.onPremisesSyncEnabled
                ActiveRoles           = [System.Collections.Generic.List[string]]::new()
                EligibleRoles         = [System.Collections.Generic.List[string]]::new()
            }
        }
        # Index the list directly: assigning an empty list from an if expression would unroll it to $null.
        if ($Kind -eq 'Active') {
            if ($RoleName -notin $users[$id].ActiveRoles) { $users[$id].ActiveRoles.Add($RoleName) }
        } else {
            if ($RoleName -notin $users[$id].EligibleRoles) { $users[$id].EligibleRoles.Add($RoleName) }
        }
    }

    function Get-GroupUserMember {
        param($GroupId)
        @(Invoke-MtGraphRequest -RelativeUri "groups/$GroupId/transitiveMembers/microsoft.graph.user" -ApiVersion v1.0 -Select id, userPrincipalName, displayName, mail, accountEnabled, userType, onPremisesSyncEnabled |
                ForEach-Object { $_ | Add-Member -NotePropertyName '@odata.type' -NotePropertyValue '#microsoft.graph.user' -Force -PassThru })
    }

    $sources = @(@{ Uri = 'roleManagement/directory/roleAssignments'; Kind = 'Active' })
    if (-not $ActiveOnly) { $sources += @{ Uri = 'roleManagement/directory/roleEligibilityScheduleInstances'; Kind = 'Eligible' } }

    foreach ($source in $sources) {
        try {
            $rows = @(Invoke-MtGraphRequest -RelativeUri $source.Uri -ApiVersion v1.0 -QueryParameters @{ '$expand' = 'principal' } -ErrorAction Stop)
        } catch {
            if ($source.Kind -eq 'Eligible') { $eligibleReadable = $false; continue }
            throw
        }
        foreach ($row in $rows) {
            $roleName = $privileged[[string]$row.roleDefinitionId]
            if (-not $roleName) { continue }
            if ($row.principal.'@odata.type' -eq '#microsoft.graph.group') {
                foreach ($member in (Get-GroupUserMember -GroupId $row.principal.id)) { Add-RoleMember -Principal $member -RoleName $roleName -Kind $source.Kind }
            } else {
                Add-RoleMember -Principal $row.principal -RoleName $roleName -Kind $source.Kind
            }
        }
    }

    foreach ($user in $users.Values) {
        $user | Add-Member -NotePropertyName Roles -NotePropertyValue @(@($user.ActiveRoles) + @($user.EligibleRoles) | Select-Object -Unique) -Force
        $user | Add-Member -NotePropertyName EligibleReadable -NotePropertyValue $eligibleReadable -Force
        $user
    }
}
