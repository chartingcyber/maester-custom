function ConvertTo-ResAssignmentSummary {
    <#
    .SYNOPSIS
    Summarises the assignments of an Intune policy into who it reaches.

    .DESCRIPTION
    Returns Scope (AllDevices, AllUsers, Groups or None), HasExclusions, IncludedGroupIds, ExcludedGroupIds and a
    one-line Text. A policy reaches everyone only when Scope is AllDevices or AllUsers and HasExclusions is $false.
    Filters on an assignment are reported in Text and count as an exclusion, because they narrow the target.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        # The assignments array of a policy or profile.
        [AllowNull()]
        [object[]] $Assignment
    )

    $includedGroups = [System.Collections.Generic.List[string]]::new()
    $excludedGroups = [System.Collections.Generic.List[string]]::new()
    $allDevices = $false
    $allUsers = $false
    $filtered = $false

    foreach ($item in @($Assignment)) {
        if ($null -eq $item) { continue }
        $target = $item.target
        $type = [string]$target.'@odata.type'
        if ($target.deviceAndAppManagementAssignmentFilterId -and $target.deviceAndAppManagementAssignmentFilterType -and $target.deviceAndAppManagementAssignmentFilterType -ne 'none') {
            $filtered = $true
        }
        switch -Wildcard ($type) {
            '*allDevicesAssignmentTarget' { $allDevices = $true }
            '*allLicensedUsersAssignmentTarget' { $allUsers = $true }
            '*exclusionGroupAssignmentTarget' { $excludedGroups.Add([string]$target.groupId) }
            '*groupAssignmentTarget' { $includedGroups.Add([string]$target.groupId) }
        }
    }

    $scope = if ($allDevices) { 'AllDevices' } elseif ($allUsers) { 'AllUsers' } elseif ($includedGroups.Count -gt 0) { 'Groups' } else { 'None' }
    $hasExclusions = ($excludedGroups.Count -gt 0) -or $filtered

    $text = switch ($scope) {
        'AllDevices' { 'All devices' }
        'AllUsers' { 'All users' }
        'Groups' { "$($includedGroups.Count) group(s)" }
        default { 'Not assigned' }
    }
    if ($excludedGroups.Count -gt 0) { $text += ", $($excludedGroups.Count) excluded group(s)" }
    if ($filtered) { $text += ', assignment filter' }

    [pscustomobject]@{
        Scope            = $scope
        HasExclusions    = $hasExclusions
        IncludedGroupIds = @($includedGroups)
        ExcludedGroupIds = @($excludedGroups)
        Text             = $text
    }
}
