Safe Links and Safe Attachments apply to every enabled user mailbox, worked out per user from the policy assignments.

Having a Safe Links or Safe Attachments policy is not the same as being protected by it. A custom policy may list only a pilot group, the Built-in protection preset may have exclusions, and the Standard and Strict presets protect nobody until users are added. For each enabled user mailbox this check applies the documented recipient logic to the Standard and Strict presets, the custom policies, and Built-in protection: values of one condition use OR, different condition types use AND, and any matching exception removes the user. A mailbox covered by none of them is listed.

Shared, room and equipment mailboxes and disabled accounts are not evaluated. ORCA.227 asks the same question per domain; this check answers it per user, including group membership read from Microsoft Graph.

Licence: Defender for Office 365 Plan 1 or Plan 2 (Plan 1 is included in Microsoft 365 Business Premium). Without it the check is skipped.

#### Remediation action

1. In the [Microsoft Defender portal](https://security.microsoft.com/presetSecurityPolicies), go to **Email & collaboration** > **Policies & rules** > **Threat policies** > **Preset Security Policies**.
2. Turn on **Standard protection** and assign it to all recipients, then assign **Strict protection** to priority accounts.
3. Under **Built-in protection**, remove exclusions unless the user has no Defender for Office 365 licence.
4. Re-run this check to confirm no mailbox is left uncovered.

#### Related links

* [Preset security policies in Microsoft 365](https://learn.microsoft.com/defender-office-365/preset-security-policies)
* [Safe Links in Microsoft Defender for Office 365](https://learn.microsoft.com/defender-office-365/safe-links-about)
* [Safe Attachments in Microsoft Defender for Office 365](https://learn.microsoft.com/defender-office-365/safe-attachments-about)

<!--- Results --->
%TestResult%
