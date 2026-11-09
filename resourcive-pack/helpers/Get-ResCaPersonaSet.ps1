function Get-ResCaPersonaSet {
    <#
    .SYNOPSIS
    Reads the tenant and returns the personas, policies and named locations that the What If scenarios need.

    .DESCRIPTION
    Reads Conditional Access policies (enabled, plus report-only when asked), named locations, the enabled users,
    the members of every group that a policy names, the active directory role assignments and the privileged
    users. Non-privileged users are grouped into equivalence classes by the policies that treat them alike, and one
    real user per class becomes a persona, together with every privileged user up to the maximum.

    With PersonaFile set, the personas are written to that JSON file after the first run and read back on later
    runs, so a run is reproducible and a persona can be edited by hand. RefreshPersonas ignores the file and writes
    it again. Policies and named locations are always read fresh, because the scenarios derive from them.

    Emergency access accounts (the EmergencyAccessAccounts setting) are recognised for every persona kind and
    tested on their own as informational. When no privileged user is found a note says that Critical expectations
    did not apply.

    Returns Personas, Policies, NamedLocations, P2Licensed, Notes and FromFile.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        # The most privileged users to test individually.
        [ValidateRange(0, 500)]
        [int] $MaxPrivilegedUsers = 25,

        # Include policies in report-only mode.
        [bool] $IncludeReportOnly = $true,

        # The most enabled users to read. Beyond this the sample is incomplete, and the result says so.
        [ValidateRange(1, 200000)]
        [int] $MaxUsers = 5000,

        # A JSON file that holds the personas between runs.
        [AllowEmptyString()]
        [string] $PersonaFile = '',

        # Ignore the persona file and write it again.
        [bool] $RefreshPersonas = $false
    )

    $notes = [System.Collections.Generic.List[string]]::new()
    $allPolicies = @(Get-MtConditionalAccessPolicy)
    $policies = @($allPolicies | Where-Object { $_.state -eq 'enabled' -or ($IncludeReportOnly -and $_.state -eq 'enabledForReportingButNotEnforced') })
    $namedLocations = @()
    try { $namedLocations = @(Invoke-MtGraphRequest -RelativeUri 'identity/conditionalAccess/namedLocations' -ApiVersion v1.0 -ErrorAction Stop) } catch {
        $notes.Add("Named locations could not be read ($($_.Exception.Message.Split("`n")[0])), so location scenarios use the default countries.")
    }
    $p2 = Test-ResLicense -ServicePlan @('AAD_PREMIUM_P2')

    $result = [pscustomobject]@{
        Personas       = @()
        Policies       = $policies
        NamedLocations = $namedLocations
        P2Licensed     = $p2
        Notes          = $notes
        FromFile       = $false
    }

    if ($PersonaFile -and -not $RefreshPersonas -and (Test-Path -LiteralPath $PersonaFile -PathType Leaf)) {
        $stored = Get-Content -LiteralPath $PersonaFile -Raw | ConvertFrom-Json -Depth 20
        $result.Personas = @($stored.Personas)
        $result.FromFile = $true
        $notes.Add("Personas were read from $PersonaFile (written $($stored.WrittenAt)). Set Resourcive.CA.RefreshPersonas to read the tenant again.")
        return $result
    }

    # Users and their memberships
    $users = @(Invoke-MtGraphRequest -RelativeUri 'users' -ApiVersion v1.0 -Filter 'accountEnabled eq true' -Select id, userPrincipalName, displayName, userType)
    if ($users.Count -gt $MaxUsers) {
        $notes.Add("The tenant has $($users.Count) enabled users; only the first $MaxUsers were sampled (Resourcive.CA.MaxUsers).")
        $users = @($users | Select-Object -First $MaxUsers)
    }
    $groupIds = @($policies | ForEach-Object { @($_.conditions.users.includeGroups) + @($_.conditions.users.excludeGroups) } | Where-Object { $_ } | Select-Object -Unique)
    $membership = Get-ResCaGroupMemberId -GroupId $groupIds
    if (@($membership['__failed']).Count -gt 0) { $notes.Add("Members of these groups could not be read, so users in them may be misclassified: $(@($membership['__failed']) -join '; ').") }
    $groupsByUser = @{}
    foreach ($gid in $groupIds) {
        foreach ($uid in @($membership[$gid])) {
            if (-not $groupsByUser.ContainsKey($uid)) { $groupsByUser[$uid] = [System.Collections.Generic.List[string]]::new() }
            $groupsByUser[$uid].Add($gid)
        }
    }
    $roles = Get-ResCaUserRoleMap
    $privileged = @(Get-ResPrivilegedUser)
    if ($privileged.Count -gt 0 -and -not $privileged[0].EligibleReadable) {
        $notes.Add('Eligible (PIM) role assignments could not be read, so privileged users who only hold eligible roles are not tested. Entra ID P2 or Governance is needed to read them.')
    }
    if ($privileged.Count -gt 0 -and @($privileged[0].UnreadableGroups).Count -gt 0) {
        $notes.Add("The members of $(@($privileged[0].UnreadableGroups).Count) group(s) that hold a privileged role could not be read and are not tested: $(@($privileged[0].UnreadableGroups) -join '; ').")
    }
    $privilegedIds = @($privileged | ForEach-Object { $_.Id })

    $candidates = foreach ($user in ($users | Where-Object { $privilegedIds -notcontains $_.id })) {
        [pscustomobject]@{
            Id                = [string]$user.id
            UserPrincipalName = [string]$user.userPrincipalName
            DisplayName       = [string]$user.displayName
            UserType          = [string]$user.userType
            GroupIds          = @($groupsByUser[[string]$user.id])
            RoleIds           = @($roles[[string]$user.id])
        }
    }
    $classes = @(Group-ResCaUserByScope -User @($candidates) -Policy $policies)

    $emergency = @()
    try {
        $emergency = @(Get-MtSetting -Name 'EmergencyAccessAccounts' | ForEach-Object { if ($_.Id) { $_.Id } else { $_.UserPrincipalName } } | Where-Object { $_ })
    } catch { $emergency = @() }

    $personas = @(Select-ResCaPersona -Class $classes -PrivilegedUser $privileged -MaxPrivilegedUsers $MaxPrivilegedUsers -EmergencyAccess $emergency)
    if ($personas.Count -gt 0 -and $personas[0].TruncatedPrivileged -gt 0) {
        $notes.Add("$($personas[0].TruncatedPrivileged) privileged users were not tested individually (Resourcive.CA.MaxPrivilegedUsers = $MaxPrivilegedUsers).")
    }
    $result.Personas = $personas
    if ($privileged.Count -eq 0) {
        $notes.Add('0 privileged users were found (no active role assignment could be read for a user), so no Critical expectation applied: the privileged persona checks and the Critical legacy-client checks did not run. Check that the role assignments are readable (RoleManagement.Read.Directory).')
    }
    $emergencyPersonas = @($personas | Where-Object { $_.IsEmergencyAccess })
    if ($emergencyPersonas.Count -gt 0) {
        $notes.Add("$($emergencyPersonas.Count) emergency access accounts (EmergencyAccessAccounts setting) are tested on their own as informational and are never used to represent a class of users.")
    }

    if ($PersonaFile) {
        try {
            [pscustomobject]@{ WrittenAt = [datetime]::UtcNow.ToString('u'); Personas = $personas } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $PersonaFile -Encoding utf8
            $notes.Add("Personas were written to $PersonaFile for the next run.")
        } catch {
            $notes.Add("The persona file $PersonaFile could not be written: $($_.Exception.Message.Split("`n")[0]).")
        }
    }
    $result
}
