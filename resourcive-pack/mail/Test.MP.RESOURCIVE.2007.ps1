function Test-ResMailConnectorsRestricted {
    <#
    .SYNOPSIS
    Checks that enabled inbound connectors do not trust mail from any sender, and lists outbound connectors that route all mail to a smart host.

    .DESCRIPTION
    An inbound connector tells Exchange Online to treat mail from a partner or on-premises server as trusted. A
    connector that matches any sender domain and is restricted by neither a list of sender IP addresses nor a TLS
    certificate name lets anyone on the internet who can reach the tenant send mail that skips parts of anti-spam
    and spoof filtering. Such an enabled connector fails the check. Outbound connectors with a smart host that
    carry mail for every recipient domain are listed for review (Investigate).
    #>
    [MaesterTest(
        Id           = 'MP.RESOURCIVE.2007',
        Title        = 'Inbound mail connectors are restricted to known senders.',
        Product      = 'exchange',
        Feature      = 'mail-flow',
        Area         = 'email-protection',
        ResourceType = 'Connector',
        Severity     = 'High',
        UserImpact   = 'Low',
        ImplementationCost = 'Medium',
        Mitre        = ('T1566', 'T1672'),
        Control      = ('nist-800-53-r5:SC-7', 'nist-800-53-r5:SI-8'),
        Service      = 'ExchangeOnline',
        License      = 'EXCHANGE_S_STANDARD'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    $inbound = @(Get-MtExo -Request InboundConnector | Where-Object { $_.Enabled })
    $outbound = @(Get-OutboundConnector -ErrorAction Stop | Where-Object { $_.Enabled })

    $open = foreach ($connector in $inbound) {
        $senderDomains = @($connector.SenderDomains | Where-Object { $_ })
        $anySender = @($senderDomains | Where-Object { $_ -match '\*' }).Count -gt 0 -or $senderDomains.Count -eq 0
        $restrictedByIp = @($connector.SenderIPAddresses | Where-Object { $_ }).Count -gt 0
        $restrictedByCert = [bool]$connector.TlsSenderCertificateName -or [bool]$connector.RestrictDomainsToCertificate
        if ($anySender -and -not $restrictedByIp -and -not $restrictedByCert) {
            [pscustomobject]@{ Connector = [string]$connector.Name; Type = [string]$connector.ConnectorType; SenderDomains = (@($connector.SenderDomains) -join ', ') }
        }
    }
    $open = @($open | Where-Object { $null -ne $_ })

    $allMailOut = @($outbound | Where-Object { @($_.SmartHosts | Where-Object { $_ }).Count -gt 0 -and (@($_.RecipientDomains) -contains '*') } |
            ForEach-Object { [pscustomobject]@{ Connector = [string]$_.Name; SmartHosts = (@($_.SmartHosts) -join ', ') } })

    $asOf = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm')
    $outText = if ($allMailOut.Count -gt 0) { "`n`nOutbound connectors that send all mail to a smart host (informational, for example a mail filtering service; confirm each is expected): $(($allMailOut | ForEach-Object { "$($_.Connector) -> $($_.SmartHosts)" }) -join '; ')." } else { '' }

    if ($open.Count -gt 0) {
        $table = "| Connector | Type | Sender domains |`n| --- | --- | --- |`n" + ((@($open) | ForEach-Object { "| $($_.Connector) | $($_.Type) | $($_.SenderDomains) |" }) -join "`n")
        Add-MtTestResultDetail -Result "$($open.Count) enabled inbound connector(s) trust mail from any sender with no IP address or certificate restriction, as of $asOf UTC.`n`n$table$outText"
        return $false
    }
    $inboundText = if ($inbound.Count -eq 0) { 'There are no enabled inbound connectors' } else { "All $($inbound.Count) enabled inbound connectors are restricted to known senders by IP address or certificate" }
    Add-MtTestResultDetail -Result "Well done. $inboundText, as of $asOf UTC.$outText"
    return $true
}
