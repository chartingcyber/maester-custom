The device registration policy limits the number of devices per user, and MFA is required to register or join a device when any user may do so.

An attacker who has a password can register a device, and a registered device can then obtain a primary refresh token and sign in without further prompts. Two controls reduce that: a limit on devices per user, which stops one account from enrolling a fleet, and an MFA requirement at registration, either in the device registration policy or with a Conditional Access policy for the user action **Register or join devices**.

The MFA requirement is not needed when device join is restricted to selected users or to nobody.

MT.1061 checks that the two MFA controls do not conflict and MT.1070 checks who may join devices.

Licence: the registration policy needs none. Reading Conditional Access needs Entra ID P1 (in Microsoft 365 Business Premium); without it that part is reported as not assessed.

#### Remediation action

1. In the [Microsoft Entra admin center](https://entra.microsoft.com), go to **Entra ID** > **Devices** > **Device settings** and set **Maximum number of devices per user** to the limit you need (20 or less).
2. Create a Conditional Access policy for the user action **Register or join devices** that requires multifactor authentication, or restrict **Users may join devices to Microsoft Entra** to selected users.

#### Related links

* [Configure device settings](https://learn.microsoft.com/entra/identity/devices/manage-device-identities)
* [Conditional Access user actions](https://learn.microsoft.com/entra/identity/conditional-access/concept-conditional-access-cloud-apps#user-actions)

<!--- Results --->
%TestResult%
