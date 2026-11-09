function Test-ResPrivilegedPhishingResistantMethod {
    <#
    .SYNOPSIS
    Checks that every enabled privileged user has registered a phishing-resistant authentication method.

    .DESCRIPTION
    Reads the authentication method registration of each user who holds a privileged Entra role (active, and eligible
    when the tenant has PIM) and checks that a phishing-resistant method is registered: a FIDO2 security key, a
    passkey, Windows Hello for Business, or certificate-based authentication. Users whose only methods are SMS, voice
    or a one-time passcode are called out. CIS 5.2.2.5 and CISA MS.AAD.3.6 check that a Conditional Access policy
    requires phishing-resistant MFA; this check checks that the administrators can satisfy it.
    #>
    [MaesterTest(
        Id           = 'MP.RESOURCIVE.3002',
        Title        = 'Privileged users have a phishing-resistant authentication method registered.',
        Product      = 'entra',
        Feature      = 'authentication-methods',
        Area         = 'privileged-access',
        ResourceType = 'User',
        Severity     = 'High',
        UserImpact   = 'Medium',
        ImplementationCost = 'Medium',
        Mitre        = ('T1566', 'T1557', 'T1111'),
        Control      = ('nist-800-53-r5:IA-2(6)'),
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
        if (-not $registration) {
            [pscustomobject]@{ User = $user.UserPrincipalName; Roles = ($user.Roles -join ', '); Status = 'Not assessed (no registration record)'; Methods = ''; Ok = $null }
            continue
        }
        $methods = @($registration.methodsRegistered | Where-Object { $_ })
        $resistant = [bool]($methods | Where-Object { $_ -match 'fido2|passKey|windowsHelloForBusiness|certificateBased' })
        $weakOnly = -not $resistant -and ($methods | Where-Object { $_ -match 'mobilePhone|alternateMobilePhone|officePhone|email|softwareOneTimePasscode|hardwareOneTimePasscode' })
        [pscustomobject]@{
            User    = $user.UserPrincipalName
            Roles   = ($user.Roles -join ', ')
            Status  = if ($resistant) { 'Phishing-resistant method registered' } elseif ($weakOnly) { 'Only phone, email or one-time passcode methods' } elseif ($methods.Count -gt 0) { 'Push or app-based MFA only' } else { 'No method registered' }
            Methods = ($methods -join ', ')
            Ok      = $resistant
        }
    }
    $rows = @($rows | Where-Object { $null -ne $_ })

    $failing = @($rows | Where-Object { $_.Ok -eq $false })
    $unknown = @($rows | Where-Object { $null -eq $_.Ok })
    $eligibleNote = if ($privileged.Count -gt 0 -and -not $privileged[0].EligibleReadable) { ' Eligible (PIM) role assignments could not be read (Entra ID P2 not available), so only active role holders were evaluated.' } else { '' }
    $summary = "$($rows.Count - $failing.Count - $unknown.Count) of $($rows.Count) privileged users have a phishing-resistant method registered, as of $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm')) UTC.$eligibleNote"

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
