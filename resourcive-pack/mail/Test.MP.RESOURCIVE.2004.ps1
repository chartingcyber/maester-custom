function Test-ResAutoForwardingBlocked {
    <#
    .SYNOPSIS
    Checks that automatic forwarding to external recipients is blocked by the outbound spam policies and the remote domain settings.

    .DESCRIPTION
    Two tenant-wide controls decide whether a user may set up automatic forwarding to the outside. Both must be off.
    - Outbound spam policies: AutoForwardingMode must not be On. Automatic means system-controlled, which blocks.
    - Remote domains: AutoForwardEnabled must be false for every remote domain, including the Default one.
    CISA.MS.EXO.1.1 covers the remote domain part. This check adds the outbound spam policies and lists both.
    #>
    [MaesterTest(
        Id           = 'MP.RESOURCIVE.2004',
        Title        = 'Automatic forwarding to external recipients is blocked tenant-wide.',
        Product      = 'exchange',
        RelatedProduct = 'defender',
        Feature      = 'mail-flow',
        Area         = 'email-protection',
        ResourceType = 'Policy',
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
    param()

    $outbound = @(Get-MtExo -Request HostedOutboundSpamFilterPolicy)
    $remote = @(Get-MtExo -Request RemoteDomain)

    $outboundRows = foreach ($policy in $outbound) {
        [pscustomobject]@{ Policy = [string]$policy.Name; Mode = [string]$policy.AutoForwardingMode; Blocks = [string]$policy.AutoForwardingMode -ne 'On' }
    }
    $remoteRows = foreach ($domain in $remote) {
        [pscustomobject]@{ Domain = [string]$domain.DomainName; Enabled = [bool]$domain.AutoForwardEnabled; Blocks = -not [bool]$domain.AutoForwardEnabled }
    }
    $failing = @(@($outboundRows | Where-Object { -not $_.Blocks }) + @($remoteRows | Where-Object { -not $_.Blocks }))

    $table = "| Outbound spam policy | AutoForwardingMode | Blocks forwarding |`n| --- | --- | --- |`n" + ((@($outboundRows) | ForEach-Object { "| $($_.Policy) | $($_.Mode) | $(if ($_.Blocks) { 'Yes' } else { 'No' }) |" }) -join "`n")
    $table += "`n`n| Remote domain | AutoForwardEnabled | Blocks forwarding |`n| --- | --- | --- |`n" + ((@($remoteRows) | ForEach-Object { "| $($_.Domain) | $($_.Enabled) | $(if ($_.Blocks) { 'Yes' } else { 'No' }) |" }) -join "`n")

    if ($failing.Count -eq 0) {
        Add-MtTestResultDetail -Result "Well done. No outbound spam policy or remote domain allows automatic forwarding to external recipients.`n`n$table"
        return $true
    }
    Add-MtTestResultDetail -Result "$($failing.Count) setting(s) allow automatic forwarding to external recipients.`n`n$table"
    return $false
}
