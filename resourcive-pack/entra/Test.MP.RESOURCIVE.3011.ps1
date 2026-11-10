function Test-ResPrivilegedMfaCapable {
    <#
    .SYNOPSIS
    Checks that every enabled privileged user can complete multifactor authentication.

    .DESCRIPTION
    Reads the authentication method registration of each enabled user who holds a privileged Entra role (active, and
    eligible when the tenant has PIM) and fails when any of them is not MFA capable: they have no second method
    registered that the tenant's authentication methods policy allows. Check 3002 asks for the stronger, phishing
    resistant methods; this check asks the basic question first, whether an administrator can do MFA at all. Users
    with no registration record are listed as not assessed.
    #>
    [MaesterTest(
        Id           = 'MP.RESOURCIVE.3011',
        Title        = 'Every privileged user is able to complete multifactor authentication.',
        Product      = 'entra',
        Feature      = 'authentication-methods',
        Area         = 'privileged-access',
        ResourceType = 'User',
        Severity     = 'High',
        UserImpact   = 'Low',
        ImplementationCost = 'Low',
        Mitre        = ('T1078', 'T1110'),
        Control      = ('nist-800-53-r5:IA-2(1)'),
        Service      = 'Graph',
        License      = 'AAD_PREMIUM',
        Permission   = ('Graph:Scope:AuditLog.Read.All', 'Graph:Scope:RoleManagement.Read.Directory')
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Assert-ResLicense -Name 'Microsoft Entra ID P1' -ServicePlan (Get-ResServicePlanName -Product EntraP1)

    try {
        $privileged = @(Get-ResPrivilegedUser | Where-Object { $_.AccountEnabled -ne $false })
        $registrations = @(Invoke-MtGraphRequest -RelativeUri 'reports/authenticationMethods/userRegistrationDetails' -ApiVersion v1.0 -ErrorAction Stop)
    } catch {
        Resolve-ResGraphError -ErrorRecord $_ -Feature 'authentication method registration details' -Requires 'AuditLog.Read.All, RoleManagement.Read.Directory and Reports Reader, Security Reader or Global Reader'
    }

    if ($privileged.Count -eq 0) {
        Add-MtTestResultDetail -SkippedBecause NotApplicable
    }

    $byId = @{}
    foreach ($registration in $registrations) { $byId[[string]$registration.id] = $registration }

    $rows = foreach ($user in $privileged) {
        $registration = $byId[[string]$user.Id]
        $status = if (-not $registration) { 'Not assessed (no registration record)' }
        elseif ($registration.isMfaCapable) { 'MFA capable' }
        elseif ($registration.isMfaRegistered) { 'MFA method registered but not usable (blocked by the authentication methods policy)' }
        else { 'Not MFA capable (no second method registered)' }
        [pscustomobject]@{
            User    = $user.UserPrincipalName
            Roles   = ($user.Roles -join ', ')
            Status  = $status
            Methods = if ($registration) { (@($registration.methodsRegistered | Where-Object { $_ }) -join ', ') } else { '' }
            Capable = if ($registration) { [bool]$registration.isMfaCapable } else { $null }
        }
    }
    $rows = @($rows)

    $failing = @($rows | Where-Object { $_.Capable -eq $false })
    $unknown = @($rows | Where-Object { $null -eq $_.Capable })
    $note = Get-ResPrivilegedUserNote -User $privileged
    $summary = "$($rows.Count - $failing.Count - $unknown.Count) of $($rows.Count) enabled privileged users can complete multifactor authentication, as of $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm')) UTC.$note"

    if ($failing.Count -eq 0 -and $unknown.Count -eq 0) {
        Add-MtTestResultDetail -Result "Well done. $summary"
        return $true
    }
    $table = "`n`n| User | Roles | Status | Methods |`n| --- | --- | --- | --- |`n" + ((@($failing) + @($unknown) | ForEach-Object { "| $($_.User) | $($_.Roles) | $($_.Status) | $($_.Methods) |" }) -join "`n")
    if ($failing.Count -eq 0) {
        Add-MtTestResultDetail -Result "$summary$table" -Investigate
        return $false
    }
    Add-MtTestResultDetail -Result "$summary$table"
    return $false
}
