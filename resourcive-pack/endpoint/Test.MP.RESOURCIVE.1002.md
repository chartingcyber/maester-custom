An Intune Windows LAPS policy backs up and rotates the local administrator password on every Windows device.

A LAPS policy that exists but is assigned to a test group, or to nobody, protects nothing. This check reads the policies that set the LAPS backup directory and works out who each one reaches. It passes only when a policy that backs up the password (to Entra ID or Active Directory) and rotates it within the allowed age is assigned to all devices or all users with no exclusion or filter. A policy that reaches only some groups is reported as **Investigate**, because the groups may or may not cover every Windows device.

MT.1177 checks the strength of a LAPS policy (backup directory, complexity, length). This check complements it with the assignment and the password age.

Licence: Microsoft Intune Plan 1 (included in Microsoft 365 Business Premium). If the tenant has no Intune licence the check is skipped.

#### Remediation action

1. In the [Microsoft Intune admin center](https://intune.microsoft.com), go to **Endpoint security** > **Account protection** > **Create policy**.
2. Choose **Windows** and **Local admin password solution (Windows LAPS)**.
3. Set **Backup Directory** to **Backup the password to Azure AD only** and set **Password Age Days** to 30 or less.
4. Assign the policy to **All devices**. Stage the rollout by assigning a pilot group first, then widen it.
5. Make sure Windows LAPS is also enabled in Entra (see MP.RESOURCIVE.1001).

#### Related links

* [Deploy Windows LAPS policy with Microsoft Intune](https://learn.microsoft.com/intune/device-security/laps/deploy-policy)
* [Microsoft Intune support for Windows LAPS](https://learn.microsoft.com/intune/device-security/laps/overview)

<!--- Results --->
%TestResult%
