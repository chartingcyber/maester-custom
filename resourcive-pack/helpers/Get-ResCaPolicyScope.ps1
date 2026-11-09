function Get-ResCaPolicyScope {
    <#
    .SYNOPSIS
    Tells whether a user is in the user scope of a Conditional Access policy.

    .DESCRIPTION
    Evaluates only the Users condition of the policy (include and exclude of users, groups, roles and guests).
    Returns Included when the policy targets the user, Excluded when it targets the user and an exclude also
    matches, and None when the policy does not target the user. The user object needs Id, UserType, GroupIds
    (the IDs of the groups the user is a member of) and RoleIds (the role template IDs the user holds).

    Guests are matched by userType, not by the specific guest or external user types the policy names, so a
    policy that targets only one guest type is treated as targeting every guest. What If decides the final
    result for each scenario; this only decides which users are sampled.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        # The user: Id, UserType, GroupIds, RoleIds.
        [Parameter(Mandatory)]
        $User,

        # The Conditional Access policy.
        [Parameter(Mandatory)]
        $Policy
    )

    $users = $Policy.conditions.users
    if (-not $users) { return 'None' }
    $isGuest = ([string]$User.UserType -eq 'Guest')
    $groupIds = @($User.GroupIds)
    $roleIds = @($User.RoleIds)

    $includeUsers = @($users.includeUsers)
    $included = $false
    if ($includeUsers -contains 'All') { $included = $true }
    elseif ($includeUsers -contains [string]$User.Id) { $included = $true }
    elseif ($isGuest -and $includeUsers -contains 'GuestsOrExternalUsers') { $included = $true }
    elseif ($isGuest -and $users.includeGuestsOrExternalUsers) { $included = $true }
    elseif (@($users.includeGroups | Where-Object { $_ -and $groupIds -contains $_ }).Count -gt 0) { $included = $true }
    elseif (@($users.includeRoles | Where-Object { $_ -and $roleIds -contains $_ }).Count -gt 0) { $included = $true }
    if (-not $included) { return 'None' }

    $excluded = $false
    if (@($users.excludeUsers) -contains [string]$User.Id) { $excluded = $true }
    elseif ($isGuest -and @($users.excludeUsers) -contains 'GuestsOrExternalUsers') { $excluded = $true }
    elseif ($isGuest -and $users.excludeGuestsOrExternalUsers) { $excluded = $true }
    elseif (@($users.excludeGroups | Where-Object { $_ -and $groupIds -contains $_ }).Count -gt 0) { $excluded = $true }
    elseif (@($users.excludeRoles | Where-Object { $_ -and $roleIds -contains $_ }).Count -gt 0) { $excluded = $true }

    if ($excluded) { 'Excluded' } else { 'Included' }
}
