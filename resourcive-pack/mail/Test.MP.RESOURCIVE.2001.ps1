function Test-ResSafeLinksAttachmentsCoverage {
    <#
    .SYNOPSIS
    Checks that Safe Links and Safe Attachments reach every enabled user mailbox, by working out which policy applies to each user.

    .DESCRIPTION
    A policy that exists is not protection. For each enabled user mailbox this evaluates the recipient conditions and
    exceptions of the Standard and Strict preset security policies, the custom Safe Links and Safe Attachments
    policies, and the Built-in protection preset security policy, using the documented logic (OR within a condition,
    AND across condition types, exceptions remove the recipient). A user covered by none of them is reported.
    ORCA.227 checks the same question per domain; this check answers it per user, including group membership.
    Group membership is read from Microsoft Graph (dynamic distribution groups are not supported by Microsoft for
    these policies and are not expanded).
    #>
    [MaesterTest(
        Id           = 'MP.RESOURCIVE.2001',
        Title        = 'Safe Links and Safe Attachments apply to every enabled user mailbox.',
        Product      = 'defender',
        RelatedProduct = 'exchange',
        Feature      = 'safe-links',
        Area         = 'email-protection',
        ResourceType = 'Mailbox',
        Severity     = 'High',
        UserImpact   = 'Low',
        ImplementationCost = 'Medium',
        Mitre        = ('T1566.001', 'T1566.002'),
        Control      = ('nist-800-53-r5:SI-8', 'nist-800-53-r5:SI-3'),
        Service      = ('ExchangeOnline', 'Graph'),
        License      = 'ATP_ENTERPRISE',
        Permission   = 'Graph:Scope:User.Read.All'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        # The most uncovered users to list in the result.
        [ValidateRange(1, 500)]
        [int] $MaximumListed = 50
    )

    Assert-ResLicense -Name 'Microsoft Defender for Office 365 Plan 1 or Plan 2' -ServicePlan (Get-ResServicePlanName -Product DefenderOffice)

    try {
        $recipients = @(Get-ResMailRecipient)
        $presetRules = @(Get-MtExo -Request ATPProtectionPolicyRule | ConvertTo-ResMailRule)
        $builtIn = @(Get-MtExo -Request ATPBuiltInProtectionRule | ConvertTo-ResMailRule -Kind BuiltIn)
        $safeLinksRules = @(Get-MtExo -Request SafeLinksRule | ConvertTo-ResMailRule -Kind Custom)
        $safeAttachmentRules = @(Get-MtExo -Request SafeAttachmentRule | ConvertTo-ResMailRule -Kind Custom)
    } catch {
        Resolve-ResGraphError -ErrorRecord $_ -Feature 'mailboxes and Defender for Office 365 rules' -Requires 'User.Read.All and an Exchange role that can read protection rules (Security Reader or View-Only Configuration)'
    }

    if ($recipients.Count -eq 0) {
        Add-MtTestResultDetail -SkippedBecause NotApplicable
    }

    $cache = @{}
    $sections = foreach ($product in @(
            @{ Name = 'Safe Links'; Rules = @($presetRules) + @($safeLinksRules) + @($builtIn) }
            @{ Name = 'Safe Attachments'; Rules = @($presetRules) + @($safeAttachmentRules) + @($builtIn) }
        )) {
        $uncovered = [System.Collections.Generic.List[object]]::new()
        $onlyBuiltIn = 0
        foreach ($recipient in $recipients) {
            $by = @($product.Rules | Where-Object { Test-ResMailRuleApplies -Rule $_ -Recipient $recipient -Cache $cache })
            if ($by.Count -eq 0) { $uncovered.Add($recipient) }
            elseif (-not ($by | Where-Object { $_.Kind -ne 'BuiltIn' })) { $onlyBuiltIn++ }
        }
        [pscustomobject]@{ Name = $product.Name; Uncovered = $uncovered; OnlyBuiltIn = $onlyBuiltIn }
    }

    $lines = foreach ($section in $sections) {
        "* **$($section.Name):** $($recipients.Count - $section.Uncovered.Count) of $($recipients.Count) mailboxes covered; $($section.Uncovered.Count) not covered; $($section.OnlyBuiltIn) covered by Built-in protection only."
    }
    $text = "Evaluated $($recipients.Count) enabled user mailboxes as of $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm')) UTC.`n`n$($lines -join "`n")"
    $unresolved = @($cache['__unresolved'] | Where-Object { $_ })
    if ($unresolved.Count -gt 0) { $text += "`n`nGroups named in a rule that could not be found in Microsoft Graph, so their members are treated as not matching: $(($unresolved | Select-Object -Unique) -join ', ')." }

    $failing = @($sections | Where-Object { $_.Uncovered.Count -gt 0 })
    if ($failing.Count -eq 0) {
        Add-MtTestResultDetail -Result "Well done. $text"
        return $true
    }
    foreach ($section in $failing) {
        $text += "`n`n**Not covered by $($section.Name):**`n`n" + ((@($section.Uncovered) | Select-Object -First $MaximumListed | ForEach-Object { "* $($_.DisplayName) ($($_.PrimarySmtpAddress))" }) -join "`n")
        if ($section.Uncovered.Count -gt $MaximumListed) { $text += "`n`nThe first $MaximumListed of $($section.Uncovered.Count) are shown." }
    }
    Add-MtTestResultDetail -Result $text
    return $false
}
