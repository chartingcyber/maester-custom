An enabled Conditional Access policy requires a compliant or hybrid joined device for all users and all apps on Windows.

Compliance policies decide whether a device is healthy. Conditional Access is what acts on the answer. Without a policy that requires a compliant device, an unmanaged or non-compliant device signs in to Microsoft 365 just as easily as a managed one. MT.1001 only checks that some policy uses device compliance. This check looks at its scope: all users, all resources (or Office 365), Windows included, and enabled (not report-only). Excluded users, groups and roles are listed so that the exceptions can be reviewed.

A policy that is in report-only mode, or limited to some users or apps, produces **Investigate**.

Licence: Microsoft Entra ID P1 and Intune Plan 1, both in Microsoft 365 Business Premium.

#### Remediation action

1. In the [Microsoft Entra admin center](https://entra.microsoft.com), go to **Entra ID** > **Conditional Access** > **Policies** > **New policy**.
2. Include **All users**, exclude your emergency access accounts, and target **All resources**.
3. Under **Grant**, choose **Require device to be marked as compliant**.
4. Start in **Report-only**, check the sign-in logs for blocked legitimate use, then set the policy to **On**.

#### Related links

* [Require compliant devices with Conditional Access](https://learn.microsoft.com/entra/identity/conditional-access/policy-all-users-device-compliance)
* [Plan a Conditional Access deployment](https://learn.microsoft.com/entra/identity/conditional-access/plan-conditional-access)

<!--- Results --->
%TestResult%
