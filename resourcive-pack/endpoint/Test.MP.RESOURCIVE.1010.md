Windows compliance policies reach every device and, together, require BitLocker, Defender, real-time protection and the firewall.

A compliance policy only matters if it is assigned, and it only protects if it requires something and acts on devices that fail it. This check reads the Windows 10 and later compliance policies and passes when the policies that reach all devices or all users, with no exclusion, together require each setting in `RequiredSettings` and at least one of them blocks a non-compliant device within `MaximumGraceDays`.

Policies assigned only to groups are listed. When they would complete the requirement the result is **Investigate**, because a person must confirm the groups cover every device.

MT.1054 checks that devices with no compliance policy are treated as not compliant. MP.RESOURCIVE.1011 checks that Conditional Access requires a compliant device, which is what makes the compliance state matter.

Licence: Intune Plan 1 (in Microsoft 365 Business Premium).

#### Remediation action

1. In the [Microsoft Intune admin center](https://intune.microsoft.com), go to **Devices** > **Compliance** > **Create policy** > **Windows 10 and later**.
2. Require **BitLocker**, **Microsoft Defender Antimalware**, **Real-time protection** and **Firewall**.
3. Under **Actions for noncompliance**, keep **Mark device noncompliant** and set the grace period to the number of days you can accept.
4. Assign the policy to **All devices**.

#### Related links

* [Device compliance settings for Windows in Intune](https://learn.microsoft.com/intune/device-security/compliance/ref-windows-settings)
* [Actions for noncompliance in Intune](https://learn.microsoft.com/intune/device-security/compliance/actions-for-noncompliance)

<!--- Results --->
%TestResult%
