function Group-ResCaUserByScope {
    <#
    .SYNOPSIS
    Groups users into equivalence classes by the set of Conditional Access policies that include or exclude them.

    .DESCRIPTION
    Two users are in the same class when every enabled or report-only policy treats them the same (included,
    excluded or not targeted) and they have the same user type. One representative of a class is enough to
    test the class, because What If would return the same policies for any of its members. Disabled policies are
    ignored. Returns one object per class with Signature, UserType, Users, and Policies (policy name and scope).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        # Users: Id, UserPrincipalName, UserType, GroupIds, RoleIds.
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $User,

        # Conditional Access policies.
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Policy
    )

    $live = @($Policy | Where-Object { $_.state -ne 'disabled' } | Sort-Object { [string]$_.id })
    $classes = [ordered]@{}
    foreach ($candidate in $User) {
        $parts = foreach ($policy in $live) {
            $scope = Get-ResCaPolicyScope -User $candidate -Policy $policy
            if ($scope -ne 'None') { '{0}={1}' -f $policy.id, $scope }
        }
        $type = if ([string]$candidate.UserType -eq 'Guest') { 'Guest' } else { 'Member' }
        $signature = ('{0}|{1}' -f $type, (@($parts) -join ','))
        if (-not $classes.Contains($signature)) {
            $classes[$signature] = [pscustomobject]@{
                Signature = $signature
                UserType  = $type
                Users     = [System.Collections.Generic.List[object]]::new()
                Policies  = @($live | ForEach-Object {
                        $scope = Get-ResCaPolicyScope -User $candidate -Policy $_
                        if ($scope -ne 'None') { '{0} ({1})' -f $_.displayName, $scope }
                    })
            }
        }
        $classes[$signature].Users.Add($candidate)
    }
    $classes.Values
}
