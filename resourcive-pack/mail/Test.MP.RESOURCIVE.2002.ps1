function Test-ResPrivilegedUsersStrictPreset {
    <#
    .SYNOPSIS
    Checks that every privileged user who has a mailbox is covered by the Strict preset security policy.

    .DESCRIPTION
    Finds the users who hold privileged Entra roles (active, and eligible when the tenant has PIM) and have an enabled
    user mailbox, then evaluates the recipient conditions and exceptions of the Strict preset security policy rules
    for built-in security features (EOP) and for Defender for Office 365. A user covered by Strict in both is
    Strict; a user covered only by Standard or by neither is reported. The Strict profile is the one Microsoft
    recommends for high-value targets.
    #>
    [MaesterTest(
        Id           = 'MP.RESOURCIVE.2002',
        Title        = 'Privileged users are covered by the Strict preset security policy.',
        Product      = 'defender',
        RelatedProduct = 'exchange',
        Feature      = 'anti-phishing',
        Area         = 'email-protection',
        ResourceType = 'User',
        Severity     = 'Medium',
        UserImpact   = 'Low',
        ImplementationCost = 'Low',
        Mitre        = ('T1566', 'T1078.004'),
        Control      = ('nist-800-53-r5:SI-8'),
        Service      = ('ExchangeOnline', 'Graph'),
        License      = 'ATP_ENTERPRISE',
        Permission   = ('Graph:Scope:RoleManagement.Read.Directory', 'Graph:Scope:User.Read.All')
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Assert-ResLicense -Name 'Microsoft Defender for Office 365 Plan 1 or Plan 2' -ServicePlan (Get-ResServicePlanName -Product DefenderOffice)

    try {
        $privileged = @(Get-ResPrivilegedUser)
        $recipients = @(Get-ResMailRecipient)
        $atpRules = @(Get-MtExo -Request ATPProtectionPolicyRule | ConvertTo-ResMailRule)
        $eopRules = @(Get-MtExo -Request EOPProtectionPolicyRule | ConvertTo-ResMailRule)
    } catch {
        Resolve-ResGraphError -ErrorRecord $_ -Feature 'privileged roles, mailboxes and preset security policy rules' -Requires 'RoleManagement.Read.Directory, User.Read.All and an Exchange role that can read protection rules'
    }

    $byAddress = @{}
    foreach ($recipient in $recipients) { foreach ($address in $recipient.Addresses) { $byAddress[$address] = $recipient } }

    function Test-ResKindApplies {
        param($Kind, $Rule, $Recipient, $Cache)
        [bool](@($Rule | Where-Object { $_.Kind -eq $Kind -and (Test-ResMailRuleApplies -Rule $_ -Recipient $Recipient -Cache $Cache) }).Count)
    }

    $cache = @{}
    $rows = foreach ($user in $privileged) {
        $recipient = $byAddress[([string]$user.UserPrincipalName).ToLowerInvariant()]
        if (-not $recipient -and $user.Mail) { $recipient = $byAddress[([string]$user.Mail).ToLowerInvariant()] }
        if (-not $recipient) { continue }
        $strict = (Test-ResKindApplies -Kind 'Strict' -Rule $atpRules -Recipient $recipient -Cache $cache) -and (Test-ResKindApplies -Kind 'Strict' -Rule $eopRules -Recipient $recipient -Cache $cache)
        $standard = (Test-ResKindApplies -Kind 'Standard' -Rule $atpRules -Recipient $recipient -Cache $cache) -or (Test-ResKindApplies -Kind 'Standard' -Rule $eopRules -Recipient $recipient -Cache $cache)
        [pscustomobject]@{
            User    = $user.UserPrincipalName
            Roles   = ($user.Roles -join ', ')
            Profile = if ($strict) { 'Strict' } elseif ($standard) { 'Standard' } else { 'Neither' }
        }
    }
    $rows = @($rows | Where-Object { $null -ne $_ })

    if ($rows.Count -eq 0) {
        Add-MtTestResultDetail -SkippedBecause NotApplicable
    }

    $notStrict = @($rows | Where-Object { $_.Profile -ne 'Strict' })
    $eligibleNote = if ($privileged.Count -gt 0 -and -not $privileged[0].EligibleReadable) { "`n`nEligible (PIM) role assignments could not be read (Entra ID P2 not available), so only active role holders were evaluated." } else { '' }
    $summary = "$($rows.Count - $notStrict.Count) of $($rows.Count) privileged users with a mailbox are covered by the Strict preset security policy, as of $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm')) UTC.$eligibleNote"

    if ($notStrict.Count -eq 0) {
        Add-MtTestResultDetail -Result "Well done. $summary"
        return $true
    }
    $table = "`n`n| User | Roles | Covered by |`n| --- | --- | --- |`n" + ((@($notStrict) | ForEach-Object { "| $($_.User) | $($_.Roles) | $($_.Profile) |" }) -join "`n")
    Add-MtTestResultDetail -Result "$summary$table"
    return $false
}
