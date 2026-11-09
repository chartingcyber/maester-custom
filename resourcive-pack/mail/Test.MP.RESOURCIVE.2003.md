No user or shared mailbox forwards its mail to an address outside the organization.

After taking over an account, attackers often set the mailbox to forward everything to an address they own. The forward survives a password reset and MFA change, so they keep reading mail. This check reads the forwarding settings of every user and shared mailbox and fails when any of them forwards to an address that is not in one of the tenant's accepted domains. Forwards to a mail contact are resolved to the contact's external address.

Internal forwards are listed for information. Tenant-wide automatic forwarding is checked by MP.RESOURCIVE.2004.

Licence: any Exchange Online mailbox licence.

#### Remediation action

1. In the [Exchange admin center](https://admin.exchange.microsoft.com/#/mailboxes), open each mailbox in the result and go to **Mail flow** > **Manage email forwarding**, and turn forwarding off.
2. Or in Exchange Online PowerShell: `Set-Mailbox -Identity <mailbox> -ForwardingSmtpAddress $null -ForwardingAddress $null -DeliverToMailboxAndForward $false`.
3. Treat any unexpected forward as an incident: review sign-in logs for the account and reset its credentials and sessions.

#### Related links

* [Configure email forwarding in Microsoft 365](https://learn.microsoft.com/exchange/recipients-in-exchange-online/manage-user-mailboxes/configure-email-forwarding)
* [Alert policies in the Microsoft Defender portal](https://learn.microsoft.com/defender-office-365/alert-policies)

<!--- Results --->
%TestResult%
