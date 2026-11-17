function Test-ResPrivilegedUserCaExclusion {
    <#
    .SYNOPSIS
    Checks that no privileged user is excluded from an enforced Conditional Access policy.

    .DESCRIPTION
    Reads the enforced Conditional Access policies that grant, block or restrict access, and for every enabled user who
    holds a privileged Entra role (active, and eligible when the tenant has PIM) works out whether a policy that
    targets them also excludes them: by user, by group or by role. An administrator excluded from a policy escapes the
    control that policy applies, which is how an exclusion made for convenience becomes the way in. Policies that
    target an administrator and exclude them are listed with the administrators they exclude.

    Emergency access accounts (the EmergencyAccessAccounts setting) are excluded from policies on purpose. They are
    listed, not exempted: when they are the only privileged users excluded, the result is Investigate so a person
    confirms that the exclusions are the intended ones and that the accounts are monitored.

    Report-only and disabled policies are not counted, because they control nothing. A guest is matched by user type,
    not by the specific guest type a policy names, so a policy that names one guest type is treated as targeting every
    guest.
    #>
    [MaesterTest(
        Id           = 'MP.RESOURCIVE.3012',
        Title        = 'No privileged user is excluded from an enforced Conditional Access policy.',
        Product      = 'entra',
        Feature      = 'conditional-access',
        Area         = 'privileged-access',
        ResourceType = 'User',
        Severity     = 'High',
        UserImpact   = 'Low',
        ImplementationCost = 'Low',
        Mitre        = ('T1078.004', 'T1556'),
        Control      = ('nist-800-53-r5:AC-6(5)'),
        Service      = 'Graph',
        License      = 'AAD_PREMIUM',
        Permission   = ('Graph:Scope:Policy.Read.All', 'Graph:Scope:RoleManagement.Read.Directory', 'Graph:Scope:GroupMember.Read.All', 'Graph:Scope:User.Read.All')
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        # Emergency access (break glass) accounts and groups. Policies exclude them on purpose; they are listed, not exempted.
        [MaesterParameter(Setting = 'EmergencyAccessAccounts')]
        [object[]] $EmergencyAccessAccounts = @()
    )

    Assert-ResLicense -Name 'Microsoft Entra ID P1' -ServicePlan (Get-ResServicePlanName -Product EntraP1)

    try {
        $privileged = @(Get-ResPrivilegedUser | Where-Object { $_.AccountEnabled -ne $false })
        $policies = @(Get-MtConditionalAccessPolicy | Where-Object { $_.state -eq 'enabled' -and ($_.grantControls -or $_.sessionControls) })
        $roleMap = Get-ResCaUserRoleMap
        $groupIds = @($policies | ForEach-Object { @($_.conditions.users.includeGroups) + @($_.conditions.users.excludeGroups) } | Where-Object { $_ } | Select-Object -Unique)
        $membership = Get-ResCaGroupMemberId -GroupId $groupIds
    } catch {
        Resolve-ResGraphError -ErrorRecord $_ -Feature 'Conditional Access policies, role assignments and group members' -Requires 'Policy.Read.All, RoleManagement.Read.Directory and GroupMember.Read.All (Global Reader covers these)'
    }

    if ($privileged.Count -eq 0 -or $policies.Count -eq 0) {
        Add-MtTestResultDetail -SkippedBecause NotApplicable
    }

    $groupsByUser = @{}
    foreach ($groupId in $groupIds) {
        foreach ($memberId in @($membership[$groupId])) {
            if (-not $groupsByUser.ContainsKey($memberId)) { $groupsByUser[$memberId] = [System.Collections.Generic.List[string]]::new() }
            $groupsByUser[$memberId].Add($groupId)
        }
    }

    # Emergency access accounts: users by ID or name, and the members of any group listed.
    $emergencyKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in @($EmergencyAccessAccounts | Where-Object { $_ })) {
        foreach ($key in @($entry.Id, $entry.UserPrincipalName)) { if ($key) { $null = $emergencyKeys.Add([string]$key) } }
        if ($entry.Type -eq 'Group' -and $entry.Id) {
            try { foreach ($memberId in @((Get-ResCaGroupMemberId -GroupId @([string]$entry.Id))[[string]$entry.Id])) { $null = $emergencyKeys.Add([string]$memberId) } } catch { }
        }
    }

    $rows = foreach ($user in $privileged) {
        $subject = [pscustomobject]@{ Id = [string]$user.Id; UserType = [string]$user.UserType; GroupIds = @($groupsByUser[[string]$user.Id]); RoleIds = @($roleMap[[string]$user.Id]) }
        $targeting = 0
        $excludedFrom = [System.Collections.Generic.List[object]]::new()
        foreach ($policy in $policies) {
            $scope = Get-ResCaPolicyScope -User $subject -Policy $policy
            if ($scope -ne 'None') { $targeting++ }
            if ($scope -eq 'Excluded') { $excludedFrom.Add($policy) }
        }
        [pscustomobject]@{
            User         = [string]$user.UserPrincipalName
            Roles        = (@($user.Roles) -join ', ')
            Targeting    = $targeting
            ExcludedFrom = @($excludedFrom)
            Emergency    = [bool]($emergencyKeys.Contains([string]$user.Id) -or $emergencyKeys.Contains([string]$user.UserPrincipalName))
            Account      = $user
        }
    }
    $rows = @($rows)
    # Add what is known about every assessed user, so a user who is not excluded shows it too.
    foreach ($row in $rows) {
        if ($row.ExcludedFrom.Count -eq 0) {
            Add-ResPrivilegedUserFact -User $row.Account -Registration $null -Fact @(
                @{ Name = 'Excluded from Conditional Access'; Value = "Not excluded from any of the $($row.Targeting) enforced policies that target this user"; Tone = 'Good'; Key = 'resourcive.caExcludedCount'; Raw = 0 }
            )
        }
    }
    $excluded = @($rows | Where-Object { $_.ExcludedFrom.Count -gt 0 })
    $regular = @($excluded | Where-Object { -not $_.Emergency })
    $asOf = (Get-Date).ToUniversalTime()
    $eligibleNote = Get-ResPrivilegedUserNote -User $privileged
    $summary = "$($rows.Count - $excluded.Count) of $($rows.Count) enabled privileged users are not excluded from any of the $($policies.Count) enforced Conditional Access policies, as of $($asOf.ToString('yyyy-MM-dd HH:mm')) UTC.$eligibleNote"

    if ($excluded.Count -eq 0) {
        Add-MtTestResultDetail -Result "Well done. $summary"
        return $true
    }

    # Name the users and the policies on the Affected objects page, with what is known about each.
    $policyUsers = @{}
    foreach ($row in $excluded) {
        $names = @($row.ExcludedFrom | ForEach-Object { $_.displayName })
        Add-ResPrivilegedUserFact -User $row.Account -Registration $null -AsOf $asOf -Fact @(
            @{ Name = 'Excluded from Conditional Access'; Value = "$($names.Count) of $($row.Targeting) policies that target this user: $($names -join '; ')"; Tone = $(if ($row.Emergency) { 'Warning' } else { 'Risk' }); Key = 'resourcive.caExcludedCount'; Raw = $names.Count }
            @{ Name = 'Emergency access account'; Value = $(if ($row.Emergency) { 'Yes, excluded on purpose' } else { 'No' }); Tone = 'Info'; Key = 'resourcive.emergencyAccess'; Raw = $row.Emergency }
        )
        foreach ($policy in $row.ExcludedFrom) {
            if (-not $policyUsers.ContainsKey($policy.id)) { $policyUsers[$policy.id] = @{ Policy = $policy; Regular = 0; Emergency = 0 } }
            if ($row.Emergency) { $policyUsers[$policy.id].Emergency++ } else { $policyUsers[$policy.id].Regular++ }
        }
    }
    foreach ($entry in $policyUsers.Values) {
        $total = $entry.Regular + $entry.Emergency
        Add-ResPolicyFact -Policy $entry.Policy -AsOf $asOf -Fact @(
            @{ Name = 'Privileged users excluded'; Value = "$total ($($entry.Regular) not emergency access)"; Tone = $(if ($entry.Regular -gt 0) { 'Risk' } else { 'Warning' }); Key = 'resourcive.privilegedExcluded'; Raw = $total }
        )
    }
    $objects = @(
        @($excluded | ForEach-Object { New-ResGraphObject -Type User -Id ([string]$_.Account.Id) -DisplayName ([string]$_.Account.DisplayName) -UserPrincipalName ([string]$_.Account.UserPrincipalName) }) +
        @($policyUsers.Values | ForEach-Object { New-ResGraphObject -Type ConditionalAccessPolicy -Id ([string]$_.Policy.id) -DisplayName ([string]$_.Policy.displayName) })
    )

    $table = "`n`n| User | Roles | Emergency access | Excluded from |`n| --- | --- | --- | --- |`n" +
        (($excluded | ForEach-Object { "| $($_.User) | $($_.Roles) | $(if ($_.Emergency) { 'Yes' } else { 'No' }) | $(@($_.ExcludedFrom | ForEach-Object { $_.displayName }) -join '; ') |" }) -join "`n")
    if ($regular.Count -eq 0) {
        Add-MtTestResultDetail -Result "Only emergency access accounts are excluded. Confirm that each exclusion is intended and that the accounts are monitored. $summary$table" -GraphObjects $objects -Investigate
        return $true
    }
    Add-MtTestResultDetail -Result "$($regular.Count) privileged user(s) are excluded from an enforced policy that targets them. $summary$table" -GraphObjects $objects
    return $false
}
