function Test-ResDeviceRegistrationControls {
    <#
    .SYNOPSIS
    Checks the device registration policy: a limit on devices per user, and MFA at device join through the policy or Conditional Access.

    .DESCRIPTION
    Reads the device registration policy. The check fails when the per-user device quota is above
    MaximumDevicesPerUser, or when any user may join devices and neither the policy's "Require multifactor
    authentication to register or join devices" nor an enabled Conditional Access policy for the user action
    "Register or join devices" requires MFA. MT.1061 checks conflicts between the two MFA controls, and MT.1070
    checks who may join; this check checks the quota and that one of the MFA controls is on.
    #>
    [MaesterTest(
        Id           = 'MP.RESOURCIVE.1013',
        Title        = 'Device registration is limited per user and requires MFA.',
        Product      = 'entra',
        Feature      = 'devices',
        Area         = 'access-control',
        ResourceType = 'Tenant',
        Severity     = 'High',
        UserImpact   = 'Low',
        ImplementationCost = 'Low',
        Mitre        = ('T1098.005', 'T1078.004'),
        Control      = ('nist-800-53-r5:IA-3', 'nist-800-53-r5:IA-2(1)'),
        Service      = 'Graph',
        Permission   = 'Graph:Scope:Policy.Read.All'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        # The most devices a single user may register or join.
        [ValidateRange(1, 100)]
        [int] $MaximumDevicesPerUser = 20
    )

    try {
        $policy = Invoke-MtGraphRequest -RelativeUri 'policies/deviceRegistrationPolicy' -ApiVersion beta -ErrorAction Stop
    } catch {
        Resolve-ResGraphError -ErrorRecord $_ -Feature 'the device registration policy' -Requires 'Policy.Read.All'
    }

    $quota = [int]$policy.userDeviceQuota
    $quotaOk = $quota -gt 0 -and $quota -le $MaximumDevicesPerUser

    $joinType = [string]$policy.azureADJoin.allowedToJoin.'@odata.type'
    $anyoneCanJoin = $joinType -like '*allDeviceRegistrationMembership'
    $policyMfa = [string]$policy.multiFactorAuthConfiguration -eq 'required'

    $caMfa = $false
    $caPolicies = @()
    $caChecked = $true
    if ((Test-ResLicense -ServicePlan (Get-ResServicePlanName -Product EntraP1)) -ne $false) {
        try {
            $caPolicies = @(Get-MtConditionalAccessPolicy | Where-Object {
                    $_.state -eq 'enabled' -and
                    (@($_.conditions.applications.includeUserActions) -contains 'urn:user:registerdevice') -and
                    (@($_.grantControls.builtInControls) -contains 'mfa' -or $_.grantControls.authenticationStrength)
                })
            $caMfa = $caPolicies.Count -gt 0
        } catch {
            $caChecked = $false
        }
    } else {
        $caChecked = $false
    }

    $mfaOk = (-not $anyoneCanJoin) -or $policyMfa -or $caMfa

    $rows = @(
        "| Devices per user | $quota (limit $MaximumDevicesPerUser) | $(if ($quotaOk) { 'OK' } else { 'Too many' }) |"
        "| Who may join devices | $(if ($anyoneCanJoin) { 'All users' } elseif ($joinType -like '*enumerated*') { 'Selected users and groups' } else { 'None' }) | |"
        "| MFA required in the device registration policy | $(if ($policyMfa) { 'Yes' } else { 'No' }) | |"
        "| Conditional Access requires MFA to register or join devices | $(if ($caMfa) { "Yes ($(@($caPolicies | ForEach-Object { $_.displayName }) -join ', '))" } elseif ($caChecked) { 'No' } else { 'Not assessed (needs Entra ID P1)' }) | |"
    )
    $table = "| Setting | Value | Result |`n| --- | --- | --- |`n" + ($rows -join "`n")

    if ($quotaOk -and $mfaOk) {
        Add-MtTestResultDetail -Result "Well done. Device registration is limited per user and MFA is required where anyone may join.`n`n$table"
        return $true
    }
    $problems = @()
    if (-not $quotaOk) { $problems += "A user may register $quota devices; the limit is $MaximumDevicesPerUser." }
    if (-not $mfaOk) { $problems += 'Any user may join devices and nothing requires MFA to do it.' }
    $text = "$($problems -join ' ')`n`n$table"
    if (-not $mfaOk -and -not $caChecked) {
        Add-MtTestResultDetail -Result "$text`n`nConditional Access could not be read, so the MFA finding may be wrong." -Investigate
    } else {
        Add-MtTestResultDetail -Result $text
    }
    return $false
}
