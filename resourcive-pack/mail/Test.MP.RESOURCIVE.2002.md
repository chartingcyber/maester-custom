Every user who holds a privileged Entra role and has a mailbox is covered by the Strict preset security policy.

Administrators are the most valuable phishing targets in a tenant: one click gives an attacker the keys. Microsoft's Strict profile is the setting it recommends for high-value targets. This check finds the users who hold privileged roles (active, and eligible where Privileged Identity Management is licensed), keeps those with an enabled user mailbox, and evaluates the recipient conditions and exceptions of the Strict preset policy rules, for both the built-in security features and Defender for Office 365. Users covered only by Standard, or by neither, are listed.

If the tenant has no Entra ID P2, eligible role assignments cannot be read and the result says so. Privileged accounts without a mailbox are not evaluated.

Licence: Defender for Office 365 Plan 1 or Plan 2 (Plan 1 is in Microsoft 365 Business Premium).

#### Remediation action

1. In the [Microsoft Defender portal](https://security.microsoft.com/presetSecurityPolicies), open **Preset Security Policies** and select **Manage protection settings** under **Strict protection**.
2. Add the users, or a group that holds them, under **Apply Strict protection to**: **Specific recipients**.
3. Add the same users as **exceptions** to Standard protection so that the precedence is unambiguous.

#### Related links

* [Preset security policies in Microsoft 365](https://learn.microsoft.com/defender-office-365/preset-security-policies)
* [Priority account protection](https://learn.microsoft.com/defender-office-365/priority-accounts-security-recommendations)

<!--- Results --->
%TestResult%
