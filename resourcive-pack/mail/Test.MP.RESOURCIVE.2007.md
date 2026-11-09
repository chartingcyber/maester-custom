Inbound mail connectors trust only known senders, and outbound connectors that carry all mail to a smart host are reviewed.

Connectors change how Exchange Online treats mail. An inbound connector from a partner or from an on-premises server marks that mail as trusted. When the connector matches any sender domain and is restricted by neither the sender's IP address nor a TLS certificate name, anyone who can reach your tenant can use it, and the mail takes the trusted path. This check fails when an enabled inbound connector is open in that way.

Outbound connectors that route every recipient domain to a smart host send all your mail through that host. They are normal for third-party mail security gateways and for hybrid, but they should be a known list, so they are listed in the result as information. They do not change the result by themselves.

Licence: any Exchange Online mailbox licence.

#### Remediation action

1. In the [Exchange admin center](https://admin.exchange.microsoft.com/#/connectors), open each connector in the result.
2. For inbound connectors, set **Authenticating sent email** to **By verifying that the IP address of the sending server matches one of these IP addresses**, or require a certificate name, and list only the partner's addresses.
3. Delete connectors that are no longer used.

#### Related links

* [Set up connectors to route mail between Microsoft 365 and your own email servers](https://learn.microsoft.com/exchange/mail-flow-best-practices/use-connectors-to-configure-mail-flow/set-up-connectors-to-route-mail)
* [Enhanced Filtering for Connectors](https://learn.microsoft.com/exchange/mail-flow-best-practices/use-connectors-to-configure-mail-flow/enhanced-filtering-for-connectors)

<!--- Results --->
%TestResult%
