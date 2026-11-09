function Test-ResMailboxForwarding {
    <#
    .SYNOPSIS
    Checks that no mailbox forwards its mail to an address outside the organization.

    .DESCRIPTION
    Reads ForwardingAddress and ForwardingSmtpAddress for every user and shared mailbox. A forward to an address whose
    domain is not an accepted domain of the tenant is external. A forward to a recipient object (ForwardingAddress)
    is resolved: a mail contact or mail user that points outside the organization is external. Mailbox forwarding set
    by an attacker is a common way to keep reading mail after the password is reset. Internal forwards are listed for
    information and do not fail the check.
    #>
    [MaesterTest(
        Id           = 'MP.RESOURCIVE.2003',
        Title        = 'No mailbox forwards mail to an external address.',
        Product      = 'exchange',
        Feature      = 'mailboxes',
        Area         = 'email-protection',
        ResourceType = 'Mailbox',
        Severity     = 'High',
        UserImpact   = 'Low',
        ImplementationCost = 'Low',
        Mitre        = ('T1114.003', 'T1020'),
        Control      = ('nist-800-53-r5:SI-4', 'nist-800-53-r5:AC-4'),
        Service      = 'ExchangeOnline',
        License      = 'EXCHANGE_S_STANDARD'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    $accepted = @(Get-MtExo -Request AcceptedDomain | ForEach-Object { ([string]$_.DomainName).ToLowerInvariant() })
    $mailboxes = @(Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox, SharedMailbox -Properties ForwardingAddress, ForwardingSmtpAddress, DeliverToMailboxAndForward |
            Where-Object { $_.ForwardingAddress -or $_.ForwardingSmtpAddress })

    function Test-ExternalAddress {
        param($Address)
        $domain = ([string]$Address -replace '^(smtp|SMTP):', '') -replace '^.*@', ''
        $domain.ToLowerInvariant() -notin $accepted
    }

    $rows = foreach ($mailbox in $mailboxes) {
        if ($mailbox.ForwardingSmtpAddress) {
            $target = [string]$mailbox.ForwardingSmtpAddress
            [pscustomobject]@{ Mailbox = $mailbox.UserPrincipalName; Target = $target -replace '^smtp:', ''; External = [bool](Test-ExternalAddress -Address $target); KeepsCopy = [bool]$mailbox.DeliverToMailboxAndForward; Source = 'ForwardingSmtpAddress' }
        }
        if ($mailbox.ForwardingAddress) {
            $recipient = Get-EXORecipient -Identity ([string]$mailbox.ForwardingAddress) -Properties ExternalEmailAddress, PrimarySmtpAddress -ErrorAction SilentlyContinue
            $target = if ($recipient.ExternalEmailAddress) { [string]$recipient.ExternalEmailAddress } elseif ($recipient.PrimarySmtpAddress) { [string]$recipient.PrimarySmtpAddress } else { [string]$mailbox.ForwardingAddress }
            $external = if ($recipient) { [bool](Test-ExternalAddress -Address $target) } else { $false }
            [pscustomobject]@{ Mailbox = $mailbox.UserPrincipalName; Target = ($target -replace '^SMTP:', ''); External = $external; KeepsCopy = [bool]$mailbox.DeliverToMailboxAndForward; Source = 'ForwardingAddress' }
        }
    }
    $rows = @($rows | Where-Object { $null -ne $_ })
    $external = @($rows | Where-Object { $_.External })
    $internal = @($rows | Where-Object { -not $_.External })

    $asOf = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm')
    $internalText = if ($internal.Count -gt 0) { "`n`nInternal forwards (not a failure): $(($internal | ForEach-Object { "$($_.Mailbox) -> $($_.Target)" }) -join '; ')." } else { '' }

    # Mailbox forwarding is configured per mailbox, but the outbound spam policy and remote domain settings can still block it in transit.
    $transportText = ''
    if ($external.Count -gt 0) {
        try {
            $policies = @(Get-MtExo -Request HostedOutboundSpamFilterPolicy)
            $remote = @(Get-MtExo -Request RemoteDomain)
            $policyBlocks = @($policies | Where-Object { [string]$_.AutoForwardingMode -eq 'On' }).Count -eq 0
            $remoteBlocks = @($remote | Where-Object { [bool]$_.AutoForwardEnabled }).Count -eq 0
            if ($policyBlocks -and $remoteBlocks) {
                $transportText = "`n`nThe outbound spam policies and remote domain settings block automatic forwarding to external recipients (see MP.RESOURCIVE.2004), so these forwards are probably stopped in transit. They are still configured and should be removed."
            } else {
                $transportText = "`n`nAutomatic forwarding to external recipients is not blocked everywhere (see MP.RESOURCIVE.2004), so these forwards can deliver mail."
            }
        } catch { $transportText = '' }
    }

    if ($external.Count -eq 0) {
        Add-MtTestResultDetail -Result "Well done. None of the user and shared mailboxes forwards mail outside the organization, as of $asOf UTC.$internalText"
        return $true
    }
    $table = "| Mailbox | Forwards to | Keeps a copy | Set with |`n| --- | --- | --- | --- |`n" + ((@($external) | ForEach-Object { "| $($_.Mailbox) | $($_.Target) | $(if ($_.KeepsCopy) { 'Yes' } else { 'No' }) | $($_.Source) |" }) -join "`n")
    Add-MtTestResultDetail -Result "$($external.Count) mailbox forward(s) go to an external address, as of $asOf UTC.`n`n$table$internalText$transportText"
    return $false
}
