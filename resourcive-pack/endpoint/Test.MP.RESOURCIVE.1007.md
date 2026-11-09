Windows devices managed by Intune report that real-time protection and tamper protection are on and that Defender signatures are current.

A policy says what should be on. The device state says what is on. Ransomware and hands-on attackers switch off real-time protection first, so a device that reports it off, or that is missing tamper protection, is both at risk and a sign that a control is not working. This check reads the Windows protection state that Intune holds for each managed device and fails when more than the allowed percentage report a problem. Devices that have not reported a state are listed as not assessed and are never counted as passing.

Tamper protection is a Defender for Endpoint capability (included in Defender for Business). Devices without it report it off.

Licence: Intune Plan 1 (in Microsoft 365 Business Premium).

#### Remediation action

1. In the [Microsoft Intune admin center](https://intune.microsoft.com), open **Devices** > **Windows** and review the devices listed in the result.
2. Turn on tamper protection: **Endpoint security** > **Antivirus** > **Windows Security experience** policy > **Tamper protection (device)** = **On**, or turn it on for the tenant in the [Microsoft Defender portal](https://security.microsoft.com/securitysettings/endpoints/advanced_features).
3. Make sure Defender Antivirus is the active antivirus and no other product or local setting turns real-time protection off. Fix signature update failures (network access to Microsoft update services).

#### Related links

* [Configure tamper protection for Microsoft Defender Antivirus on Windows](https://learn.microsoft.com/defender-endpoint/tamper-protection-windows-configure)
* [windowsProtectionState resource type](https://learn.microsoft.com/graph/api/resources/intune-devices-windowsprotectionstate)

<!--- Results --->
%TestResult%
