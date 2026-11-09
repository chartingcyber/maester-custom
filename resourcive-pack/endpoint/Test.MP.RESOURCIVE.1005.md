Every attack surface reduction (ASR) rule is in **Block** mode for all Windows devices.

ASR rules stop behaviour that malware depends on, such as Office applications starting child processes, credential theft from LSASS, and obfuscated scripts. MT.1178 checks the three rules in Microsoft's Standard Protection set. This check covers the full set that Intune exposes, and it checks who each rule reaches, because a rule in Block mode for a pilot group protects only that group.

For each rule the status is **Enforced** (Block, all devices or all users), **Partial scope** (Block for some groups only), **Audit-only** (Audit or Warn), **Not assigned** or **Not configured**. The check fails when a required rule is not enforced for everyone and is **Investigate** when the only gaps are partial scope. The rule that applies to Windows Server only (Block Webshell creation for Servers) and the rules Microsoft still lists as preview are shown but not required. A rule that a policy sets to Off is shown as **Disabled**. Use the `RulesNotRequired` parameter for rules your business cannot enforce, and say why in your run configuration.

The exclusions configured in the same policies are listed, so that old exclusions can be reviewed.

Licence: Intune Plan 1 and Microsoft Defender for Business or Defender for Endpoint (both in Microsoft 365 Business Premium).

#### Remediation action

1. In the [Microsoft Intune admin center](https://intune.microsoft.com), go to **Endpoint security** > **Attack surface reduction**.
2. Create or edit a policy for **Windows** > **Attack surface reduction rules**.
3. Set each rule to **Block**. Start the rules that Microsoft does not list as Standard Protection in **Audit** mode and review the ASR report in the Microsoft Defender portal before switching to Block.
4. Assign the policy to **All devices** and keep exclusions to the minimum.

#### Related links

* [Attack surface reduction rules reference](https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference)
* [Attack surface reduction rules deployment guide](https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-deployment)

<!--- Results --->
%TestResult%
