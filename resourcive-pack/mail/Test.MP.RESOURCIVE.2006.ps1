function Test-ResTransportRulesExternalCopy {
    <#
    .SYNOPSIS
    Checks that no enabled mail flow (transport) rule redirects, blind copies, copies or adds an external recipient.

    .DESCRIPTION
    A transport rule that sends a copy of mail to an outside address is a tenant-wide, invisible forwarder. This reads
    the transport rules and flags every enabled rule with an external address in RedirectMessageTo, BlindCopyTo,
    CopyTo or AddToRecipients. Only addresses are classified: recipient names that cannot be
    resolved to an address are listed separately for review. Rules with SetSCL set to -1 are covered by MT.1043.
    #>
    [MaesterTest(
        Id           = 'MP.RESOURCIVE.2006',
        Title        = 'No enabled transport rule sends mail to an external recipient.',
        Product      = 'exchange',
        Feature      = 'mail-flow',
        Area         = 'email-protection',
        ResourceType = 'MailFlowRule',
        Severity     = 'High',
        UserImpact   = 'Low',
        ImplementationCost = 'Low',
        Mitre        = ('T1114.003', 'T1020'),
        Control      = ('nist-800-53-r5:AC-4', 'nist-800-53-r5:SI-4'),
        Service      = 'ExchangeOnline',
        License      = 'EXCHANGE_S_STANDARD'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        # External addresses or domains that a rule may send to, for example a ticketing system's support address.
        # A match is listed as allowed and does not fail the check.
        [string[]] $AllowedExternal = @()
    )

    $allowed = @($AllowedExternal | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } | Where-Object { $_ })

    $accepted = @(Get-MtExo -Request AcceptedDomain | ForEach-Object { ([string]$_.DomainName).ToLowerInvariant() })
    $rules = @(Get-MtExo -Request TransportRule | Where-Object { $_.State -eq 'Enabled' })

    $actions = 'RedirectMessageTo', 'BlindCopyTo', 'CopyTo', 'AddToRecipients'
    $findings = [System.Collections.Generic.List[object]]::new()
    $unresolved = [System.Collections.Generic.List[object]]::new()
    $allowedHits = [System.Collections.Generic.List[object]]::new()
    foreach ($rule in $rules) {
        foreach ($action in $actions) {
            foreach ($value in @($rule.$action | Where-Object { $_ })) {
                $text = [string]$value
                if ($text -match '@') {
                    $domain = ($text -replace '^.*@', '').Trim().ToLowerInvariant()
                    $isAllowed = ($text.Trim().ToLowerInvariant() -in $allowed) -or ($domain -in $allowed)
                    if ($domain -notin $accepted -and $isAllowed) { $allowedHits.Add([pscustomobject]@{ Rule = [string]$rule.Name; Action = $action; Target = $text }) }
                    elseif ($domain -notin $accepted) { $findings.Add([pscustomobject]@{ Rule = [string]$rule.Name; Action = $action; Target = $text; Priority = $rule.Priority }) }
                } else {
                    $unresolved.Add([pscustomobject]@{ Rule = [string]$rule.Name; Action = $action; Target = $text })
                }
            }
        }
    }

    $note = if ($unresolved.Count -gt 0) { "`n`nRecipients given by name, not address, so not classified (check that none is a mail contact outside the organization): $(($unresolved | ForEach-Object { "$($_.Rule) $($_.Action) $($_.Target)" }) -join '; ')." } else { '' }
    $allowedNote = if ($allowedHits.Count -gt 0) { "`n`nAllowed by the AllowedExternal parameter: $(($allowedHits | ForEach-Object { "$($_.Rule) $($_.Action) $($_.Target)" }) -join '; ')." } else { '' }
    $note += $allowedNote
    $asOf = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm')
    if ($findings.Count -eq 0) {
        Add-MtTestResultDetail -Result "Well done. None of the $($rules.Count) enabled transport rules sends mail to an external address, as of $asOf UTC.$note"
        return $true
    }
    $table = "| Rule | Action | External recipient | Priority |`n| --- | --- | --- | --- |`n" + ((@($findings) | ForEach-Object { "| $($_.Rule) | $($_.Action) | $($_.Target) | $($_.Priority) |" }) -join "`n")
    Add-MtTestResultDetail -Result "$($findings.Count) transport rule action(s) send mail to an external address, as of $asOf UTC.`n`n$table$note"
    return $false
}
