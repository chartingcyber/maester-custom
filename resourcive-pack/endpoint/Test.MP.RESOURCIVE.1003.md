USB mass storage and other removable storage is blocked by an enforcing policy that reaches every Windows device.

Removable drives are a way to bring malware in, to take data out, and to plant a device that attacks on connection. A control that is only set in audit mode, or assigned to a pilot group, does not stop any of that. This check reads every place Intune can block removable storage and reports one status for the control:

* **Enforced**: an enforcing policy reaches all devices or all users with no exclusion or filter.
* **Partial scope**: an enforcing policy exists but reaches only some groups. The result is **Investigate**.
* **Audit-only**, **Not assigned**, **Not configured**: the check fails.

Mechanisms read: the Storage CSP *RemovableDiskDenyWriteAccess* (settings catalog, Device restrictions template, custom OMA-URI), Administrative Templates under *Removable Storage Access*, Defender for Endpoint device control *DefaultEnforcement* = Deny, and the Device restrictions *removable storage* block.

Not evaluated: the individual rules inside an Intune **Device Control** profile (reusable groups and entries). When such a profile exists and nothing else enforces, the result is **Investigate** so that a person can read the rules.

Licence: Intune Plan 1 (in Microsoft 365 Business Premium). Defender for Endpoint device control is a Plan 1 capability and is in Defender for Business.

#### Remediation action

1. In the [Microsoft Intune admin center](https://intune.microsoft.com), go to **Endpoint security** > **Attack surface reduction** > **Create policy** > **Windows** > **Attack surface reduction rules** (or **Device Control**).
2. Set **Block write access to removable storage** to **Yes**, or create a Device Control policy with a Deny rule for removable media.
3. If staff need USB drives, allow specific approved devices with a Device Control allow rule instead of leaving the control off.
4. Assign the policy to **All devices**. Pilot first with a group, then widen the assignment.

#### Related links

* [Device control in Microsoft Defender for Endpoint](https://learn.microsoft.com/defender-endpoint/device-control-overview)
* [Configure device control in Microsoft Defender for Endpoint](https://learn.microsoft.com/defender-endpoint/device-control-configure)
* [Policy CSP - Storage: RemovableDiskDenyWriteAccess](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-storage#removablediskdenywriteaccess)

<!--- Results --->
%TestResult%
