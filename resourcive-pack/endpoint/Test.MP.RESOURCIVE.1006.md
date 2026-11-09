The core Microsoft Defender Antivirus protections are turned on by a policy that reaches every Windows device.

Defender Antivirus is on by default, but a policy, a third-party product or a local change can turn protections off. A policy that sets the protections and is assigned to all devices keeps them on, and makes any drift visible. This check reads the settings catalog policies and reports each of these as Enforced, Partial scope, Not assigned or Not configured: real-time protection, behavior monitoring, cloud-delivered protection, scanning of downloaded files and attachments, network protection (block mode), and potentially unwanted application protection (block mode).

A protection that is on by Windows default but not set by a policy is reported as **Not configured**: the check cannot see device defaults. MP.RESOURCIVE.1007 checks the actual state on each device.

Script scanning has its own check, MT.1152.

Licence: Intune Plan 1 (in Microsoft 365 Business Premium).

#### Remediation action

1. In the [Microsoft Intune admin center](https://intune.microsoft.com), go to **Endpoint security** > **Antivirus** > **Create policy** > **Windows** > **Microsoft Defender Antivirus**.
2. Turn on **Real-time protection**, **Behavior monitoring**, **Cloud protection** and **Scan downloaded files and attachments**. Set **Network protection** and **PUA protection** to **Block**.
3. Assign the policy to **All devices**.

#### Related links

* [Antivirus policy for endpoint security in Intune](https://learn.microsoft.com/intune/device-configuration/endpoint-security/antivirus)
* [Microsoft Defender Antivirus documentation](https://learn.microsoft.com/defender-endpoint/microsoft-defender-antivirus-windows)

<!--- Results --->
%TestResult%
