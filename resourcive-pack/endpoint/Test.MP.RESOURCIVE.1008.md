A BitLocker policy reaches every Windows device, and the managed Windows devices report that their drives are encrypted.

A lost or stolen laptop with an unencrypted drive is a data breach. This check looks at the control from both sides. The **policy** view reads the Intune disk encryption policies and reports whether one that requires device encryption is assigned to all devices. The **device** view reads the encryption state that each managed Windows device reports. The check passes when both are in order.

MT.1123 checks the quality of the BitLocker settings, such as full disk encryption. Use it together with this check.

A policy that reaches only some groups is reported as **Investigate**. Devices that report that they are not encrypted are listed so that they can be fixed one by one.

Licence: Intune Plan 1 (in Microsoft 365 Business Premium).

#### Remediation action

1. In the [Microsoft Intune admin center](https://intune.microsoft.com), go to **Endpoint security** > **Disk encryption** > **Create policy** > **Windows** > **BitLocker**.
2. Set **Require Device Encryption** to **Enabled** and choose strong encryption methods. Turn on recovery key backup to Microsoft Entra ID.
3. Assign the policy to **All devices**.
4. For each device in the result, check the policy applied, the TPM state and that the user is not blocked by a conflicting local policy.

#### Related links

* [Disk encryption policy for endpoint security in Intune](https://learn.microsoft.com/intune/device-configuration/endpoint-security/disk-encryption)
* [Encrypt Windows devices with BitLocker using Intune](https://learn.microsoft.com/intune/device-security/bitlocker/encrypt-devices)

<!--- Results --->
%TestResult%
