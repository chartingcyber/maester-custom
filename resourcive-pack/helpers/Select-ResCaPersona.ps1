function Select-ResCaPersona {
    <#
    .SYNOPSIS
    Chooses the real users that the What If scenarios sign in as.

    .DESCRIPTION
    Every privileged user is a persona of their own, up to the maximum, ordered by user principal name. Each
    equivalence class of other users contributes one representative: the first member by user principal name,
    so the choice is stable between runs. Classes are numbered by size, largest first.

    Emergency access accounts (EmergencyAccess: object IDs or user principal names) are recognised for every
    persona kind. They are left out of the representative pool, so a class is never represented by a break-glass
    account, and the ones found in a class become personas of their own (Key emerg-NN, Label Emergency:Member or
    Emergency:Guest) with IsEmergencyAccess set, which the scenarios treat as informational. A class made only of
    emergency accounts has no representative. ClassSize counts the users of the class without them.

    Returns persona objects with Key, Kind (Privileged, Member or Guest), Label, UserId, UserPrincipalName,
    DisplayName, Roles, ClassSize, ClassPolicies and IsEmergencyAccess. A persona list that was cut by the
    maximum has TruncatedPrivileged on its first element.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        # Equivalence classes from Group-ResCaUserByScope, built from users who hold no privileged role.
        [AllowEmptyCollection()]
        [object[]] $Class = @(),

        # Privileged users from Get-ResPrivilegedUser.
        [AllowEmptyCollection()]
        [object[]] $PrivilegedUser = @(),

        # The most privileged users to test individually.
        [ValidateRange(0, 500)]
        [int] $MaxPrivilegedUsers = 25,

        # Object IDs or user principal names of emergency access accounts, which policies exclude by design.
        [string[]] $EmergencyAccess = @()
    )

    $personas = [System.Collections.Generic.List[object]]::new()
    $emergency = @($EmergencyAccess | ForEach-Object { ([string]$_).ToLowerInvariant() })

    $ordered = @($PrivilegedUser | Sort-Object { [string]$_.UserPrincipalName })
    $index = 0
    foreach ($user in ($ordered | Select-Object -First $MaxPrivilegedUsers)) {
        $index++
        $roles = @($user.Roles)
        $isEmergency = ($emergency -contains ([string]$user.Id).ToLowerInvariant()) -or ($emergency -contains ([string]$user.UserPrincipalName).ToLowerInvariant())
        $personas.Add([pscustomobject]@{
                Key               = 'priv-{0:00}' -f $index
                Kind              = 'Privileged'
                Label             = 'Privileged:{0}' -f $(if ($roles.Count -gt 0) { ($roles[0] -replace '\s', '') } else { 'Unknown' })
                UserId            = [string]$user.Id
                UserPrincipalName = [string]$user.UserPrincipalName
                DisplayName       = [string]$user.DisplayName
                Roles             = $roles
                ClassSize         = 1
                ClassPolicies     = @()
                IsEmergencyAccess = $isEmergency
            })
    }

    function Test-Emergency { param($User) ($emergency -contains ([string]$User.Id).ToLowerInvariant()) -or ($emergency -contains ([string]$User.UserPrincipalName).ToLowerInvariant()) }
    $emergencyUsers = [System.Collections.Generic.List[object]]::new()
    foreach ($kind in 'Member', 'Guest') {
        $n = 0
        $kindClasses = @($Class | Where-Object { $_.UserType -eq $kind } |
                Sort-Object @{ Expression = { $_.Users.Count }; Descending = $true }, @{ Expression = { $_.Signature } })
        foreach ($c in $kindClasses) {
            $members = @($c.Users | Where-Object { -not (Test-Emergency $_) })
            foreach ($u in @($c.Users | Where-Object { Test-Emergency $_ })) { $emergencyUsers.Add([pscustomobject]@{ User = $u; Kind = $kind; Policies = @($c.Policies) }) }
            if ($members.Count -eq 0) { continue }
            $n++
            $rep = @($members | Sort-Object { [string]$_.UserPrincipalName })[0]
            $personas.Add([pscustomobject]@{
                    Key               = ('{0}-c{1:00}' -f $kind.ToLowerInvariant(), $n)
                    Kind              = $kind
                    Label             = ('{0}:class-{1}' -f $kind, $n)
                    UserId            = [string]$rep.Id
                    UserPrincipalName = [string]$rep.UserPrincipalName
                    DisplayName       = [string]$rep.DisplayName
                    Roles             = @()
                    ClassSize         = $members.Count
                    ClassPolicies     = @($c.Policies)
                    IsEmergencyAccess = $false
                })
        }
    }
    $e = 0
    foreach ($item in ($emergencyUsers | Sort-Object { [string]$_.User.UserPrincipalName })) {
        $e++
        $personas.Add([pscustomobject]@{
                Key               = 'emerg-{0:00}' -f $e
                Kind              = $item.Kind
                Label             = 'Emergency:{0}' -f $item.Kind
                UserId            = [string]$item.User.Id
                UserPrincipalName = [string]$item.User.UserPrincipalName
                DisplayName       = [string]$item.User.DisplayName
                Roles             = @()
                ClassSize         = 1
                ClassPolicies     = @($item.Policies)
                IsEmergencyAccess = $true
            })
    }
    if ($personas.Count -gt 0) {
        $personas[0] | Add-Member -NotePropertyName TruncatedPrivileged -NotePropertyValue ([Math]::Max(0, $ordered.Count - $MaxPrivilegedUsers)) -Force
    }
    $personas.ToArray()
}
