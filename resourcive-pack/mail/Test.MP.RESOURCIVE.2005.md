No inbox rule forwards mail outside the organization or hides mail that an attacker does not want the owner to see.

Inbox rules are the second favourite persistence trick after forwarding. An attacker who has a mailbox creates a rule that forwards copies out, or that moves or deletes replies to messages about invoices, payments or security alerts so the owner never notices. Some rules are hidden from the Outlook rules list. This check reads each mailbox's inbox rules, hidden ones included, and flags rules that forward, redirect or forward as attachment outside the accepted domains, rules that hide mail with words attackers use, and rules with an empty or one-character name.

By default only users who hold privileged roles are scanned, because the scan is one call per mailbox and the check is marked long-running. Use `Scope = All` for the whole tenant, up to `MaximumMailboxes`. Mailboxes that cannot be read are counted as not assessed.

Reading inbox rules of other users needs an Exchange role beyond Global Reader (for example View-Only Recipients or Mail Recipients); confirm in your tenant.

Licence: any Exchange Online mailbox licence.

#### Remediation action

1. In Exchange Online PowerShell, review the rule: `Get-InboxRule -Mailbox <user> -IncludeHidden | Format-List`.
2. Remove a malicious rule: `Remove-InboxRule -Mailbox <user> -Identity <rule id>`.
3. Treat a malicious rule as a compromise: reset the password, revoke sessions, review sign-in logs and consent grants, and check for other persistence.

#### Related links

* [Detect and remediate Outlook rules and custom forms injections attacks](https://learn.microsoft.com/microsoft-365/security/office-365-security/detect-and-remediate-outlook-rules-forms-attack)
* [Get-InboxRule](https://learn.microsoft.com/powershell/module/exchangepowershell/get-inboxrule)

<!--- Results --->
%TestResult%
