Untrusted scripts are blocked on all Windows devices, by attack surface reduction (ASR) script rules or by App Control for Business.

Script hosts (PowerShell, wscript, cscript, mshta) are the most common way for phishing payloads to run code without a file that antivirus recognises. This check passes when either of these is true for all devices or all users, with no exclusions:

* The ASR rules **Block execution of potentially obfuscated scripts** and **Block JavaScript or VBScript from launching downloaded executable content** are both in **Block** mode.
* An App Control for Business policy is **enforcing** (audit mode is off).

Audit and Warn modes do not block, so they fail the check. A control assigned only to some groups is reported as **Investigate**.

Not assessed: PowerShell Constrained Language Mode. It is a device setting and cannot be read from tenant configuration, so this check does not claim anything about it.

Licence: Intune Plan 1 and Microsoft Defender for Business or Defender for Endpoint (both in Microsoft 365 Business Premium). Without them the check is skipped.

#### Remediation action

1. In the [Microsoft Intune admin center](https://intune.microsoft.com), go to **Endpoint security** > **Attack surface reduction** > **Create policy** > **Windows** > **Attack surface reduction rules**.
2. Set the two script rules to **Block**. Use **Audit** for a week first if you have scripted business processes, and review the audit events.
3. Assign the policy to **All devices**.
4. For stronger protection, deploy an App Control for Business policy under **Endpoint security** > **Application control** with audit mode off.

#### Related links

* [Attack surface reduction rules reference](https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference)
* [Attack surface reduction rules deployment guide](https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-deployment)
* [App Control for Business](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/appcontrol)

<!--- Results --->
%TestResult%
