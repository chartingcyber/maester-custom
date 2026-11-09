Automatic forwarding to external recipients is blocked by the outbound spam policies and by every remote domain.

Whether a user can forward mail to the outside is decided in two places, and an attacker needs only one of them to be open. In the outbound spam policies, **Automatic forwarding rules** must not be **On** (the default, **Automatic - System-controlled**, blocks it). In the remote domains, **Allow automatic forwarding** must be off for every domain, including the Default one. This check lists both.

CISA.MS.EXO.1.1 checks the remote domains. Together with MP.RESOURCIVE.2003, which finds forwards that already exist, this closes the forwarding path.

Licence: any Exchange Online mailbox licence.

#### Remediation action

1. In the [Microsoft Defender portal](https://security.microsoft.com/antispam), open **Email & collaboration** > **Policies & rules** > **Threat policies** > **Anti-spam** > **Anti-spam outbound policy** and set **Automatic forwarding rules** to **Automatic - System-controlled** or **Off**.
2. In the [Exchange admin center](https://admin.exchange.microsoft.com/#/remotedomains), open each remote domain and clear **Allow automatic forwarding**.
3. If a business process needs forwarding for specific mailboxes, create an outbound spam policy for those mailboxes only.

#### Related links

* [Control automatic external email forwarding in Microsoft 365](https://learn.microsoft.com/defender-office-365/outbound-spam-policies-external-email-forwarding)
* [Remote domains in Exchange Online](https://learn.microsoft.com/exchange/mail-flow-best-practices/remote-domains/remote-domains)

<!--- Results --->
%TestResult%
