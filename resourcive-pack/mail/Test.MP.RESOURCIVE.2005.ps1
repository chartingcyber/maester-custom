function Test-ResSuspiciousInboxRules {
    <#
    .SYNOPSIS
    Checks the inbox rules of privileged users (or all mailboxes) for rules that forward outside the organization or hide mail.

    .DESCRIPTION
    Reads each mailbox's inbox rules, hidden rules included (Get-InboxRule -IncludeHidden), and flags:
    - rules that forward, redirect or forward as attachment to an address outside the accepted domains;
    - rules that delete messages, or move them to Deleted Items, RSS Feeds, Conversation History or Junk Email, and that
      are enabled and match on words attackers use to hide replies (invoice, payment, wire, password, security, phish);
    - rules whose name is empty or a single character, and hidden rules.
    The scan is per mailbox and slow in a large tenant, so by default only privileged users are scanned and the check
    is long-running. Set Scope to All to scan every user mailbox, up to MaximumMailboxes.
    #>
    [MaesterTest(
        Id           = 'MP.RESOURCIVE.2005',
        Title        = 'No mailbox has an inbox rule that forwards externally or hides mail.',
        Product      = 'exchange',
        Feature      = 'mailboxes',
        Area         = 'email-protection',
        ResourceType = 'Mailbox',
        Severity     = 'High',
        UserImpact   = 'Low',
        ImplementationCost = 'Low',
        Mitre        = ('T1114.003', 'T1564.008'),
        Control      = ('nist-800-53-r5:SI-4'),
        Service      = ('ExchangeOnline', 'Graph'),
        License      = 'EXCHANGE_S_STANDARD',
        LongRunning
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        # Which mailboxes to scan: Privileged (holders of privileged roles) or All (every user mailbox).
        [ValidateSet('Privileged', 'All')]
        [string] $Scope = 'Privileged',

        # The most mailboxes to scan when Scope is All.
        [ValidateRange(1, 10000)]
        [int] $MaximumMailboxes = 500,

        # Words that, in a rule that hides mail, point to an attacker.
        [string[]] $SuspiciousWords = @('invoice', 'payment', 'wire', 'password', 'security', 'phish', 'suspicious', 'unusual', 'verify', 'bank')
    )

    $accepted = @(Get-MtExo -Request AcceptedDomain | ForEach-Object { ([string]$_.DomainName).ToLowerInvariant() })
    $recipients = @(Get-ResMailRecipient)

    $targets = if ($Scope -eq 'Privileged') {
        $byAddress = @{}
        foreach ($recipient in $recipients) { foreach ($address in $recipient.Addresses) { $byAddress[$address] = $recipient } }
        @(Get-ResPrivilegedUser | ForEach-Object {
                $r = $byAddress[([string]$_.UserPrincipalName).ToLowerInvariant()]
                if (-not $r -and $_.Mail) { $r = $byAddress[([string]$_.Mail).ToLowerInvariant()] }
                $r
            } | Where-Object { $_ } | Select-Object -Unique)
    } else {
        @($recipients | Select-Object -First $MaximumMailboxes)
    }

    if ($targets.Count -eq 0) {
        Add-MtTestResultDetail -SkippedBecause NotApplicable
    }

    function Test-ExternalAddress {
        param($Value)
        $text = [string]$Value
        if ($text -notmatch '@') { return $false }
        (($text -replace '^.*<', '' -replace '>.*$', '' -replace '^.*@', '').Trim().ToLowerInvariant()) -notin $accepted
    }
    $hidingFolders = 'Deleted Items|RSS|Conversation History|Junk'

    $findings = [System.Collections.Generic.List[object]]::new()
    $errors = 0
    foreach ($target in $targets) {
        try {
            $rules = @(Get-InboxRule -Mailbox $target.UserPrincipalName -IncludeHidden -ErrorAction Stop)
        } catch {
            $errors++
            continue
        }
        foreach ($rule in $rules) {
            if (-not $rule.Enabled) { continue }
            $targetsOut = @(@($rule.ForwardTo) + @($rule.RedirectTo) + @($rule.ForwardAsAttachmentTo) | Where-Object { $_ })
            $external = @($targetsOut | Where-Object { Test-ExternalAddress -Value $_ })
            $text = (@($rule.SubjectContainsWords) + @($rule.BodyContainsWords) + @($rule.SubjectOrBodyContainsWords) + @($rule.FromAddressContainsWords) | Where-Object { $_ }) -join ' '
            $hides = [bool]$rule.DeleteMessage -or ([string]$rule.MoveToFolder -match $hidingFolders)
            $words = @($SuspiciousWords | Where-Object { $text -match [regex]::Escape($_) })
            $reason = @()
            if ($external.Count -gt 0) { $reason += "forwards to $($external -join ', ')" }
            if ($hides -and $words.Count -gt 0) { $reason += "hides mail matching: $($words -join ', ')" }
            if (([string]$rule.Name).Trim().Length -le 1) { $reason += 'has an empty or one-character name' }
            if ($reason.Count -gt 0) {
                $findings.Add([pscustomobject]@{ Mailbox = $target.UserPrincipalName; Rule = [string]$rule.Name; Reason = ($reason -join '; ') })
            }
        }
    }

    $summary = "Scanned $($targets.Count - $errors) of $($targets.Count) mailbox(es) (scope: $Scope) as of $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm')) UTC."
    if ($errors -gt 0) { $summary += " $errors mailbox(es) could not be read and are not assessed; reading inbox rules needs an Exchange role such as View-Only Recipients or Mail Recipients." }

    if ($findings.Count -eq 0) {
        if ($errors -eq $targets.Count) {
            Add-MtTestResultDetail -Result "$summary Nothing could be assessed." -Investigate
            return $false
        }
        Add-MtTestResultDetail -Result "Well done. No inbox rule forwards externally or hides mail. $summary"
        return $true
    }
    $table = "| Mailbox | Rule | Why it is flagged |`n| --- | --- | --- |`n" + ((@($findings) | ForEach-Object { "| $($_.Mailbox) | $($_.Rule) | $($_.Reason) |" }) -join "`n")
    Add-MtTestResultDetail -Result "$($findings.Count) inbox rule(s) are suspicious. $summary`n`n$table"
    return $false
}
