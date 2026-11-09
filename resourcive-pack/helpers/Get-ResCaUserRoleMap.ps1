function Get-ResCaUserRoleMap {
    <#
    .SYNOPSIS
    Returns the directory role template IDs each user holds through active role assignments.

    .DESCRIPTION
    Conditional Access targets roles by template ID, so every active assignment is read (not only privileged
    roles), with the principal expanded. Role-assignable groups are expanded to their user members. Eligible (PIM)
    assignments are not counted: Conditional Access applies a role condition to the roles a user holds when they
    sign in. Returns a hashtable of user ID to role definition ID list.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    $map = @{}
    function Add-RoleToUser {
        param($UserId, $RoleId)
        if (-not $map.ContainsKey($UserId)) { $map[$UserId] = [System.Collections.Generic.List[string]]::new() }
        if ($RoleId -notin $map[$UserId]) { $map[$UserId].Add($RoleId) }
    }
    $rows = @(Invoke-MtGraphRequest -RelativeUri 'roleManagement/directory/roleAssignments' -ApiVersion v1.0 -QueryParameters @{ '$expand' = 'principal' })
    foreach ($row in $rows) {
        $type = [string]$row.principal.'@odata.type'
        if ($type -eq '#microsoft.graph.user') {
            Add-RoleToUser -UserId ([string]$row.principalId) -RoleId ([string]$row.roleDefinitionId)
        } elseif ($type -eq '#microsoft.graph.group') {
            $members = Get-ResCaGroupMemberId -GroupId @([string]$row.principalId)
            foreach ($memberId in @($members[[string]$row.principalId])) { Add-RoleToUser -UserId $memberId -RoleId ([string]$row.roleDefinitionId) }
        }
    }
    $result = @{}
    foreach ($key in $map.Keys) { $result[$key] = $map[$key].ToArray() }
    $result
}
