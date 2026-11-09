Windows LAPS is turned on in the Microsoft Entra device settings.

Windows LAPS gives every device a unique, regularly rotated local administrator password. For Entra joined devices the password is stored in Entra ID, but only when the tenant setting is on. With it off, the Intune LAPS policy is accepted by the device and then has nowhere to store the password. A shared or stale local administrator password lets an attacker move from one device to the next.

Windows LAPS needs no licence beyond Entra ID Free. The Intune policy that configures it needs Intune Plan 1 (see MP.RESOURCIVE.1002).

#### Remediation action

1. Sign in to the [Microsoft Entra admin center](https://entra.microsoft.com) as at least a Cloud Device Administrator.
2. Go to **Entra ID** > **Devices** > **Overview** > [**Device settings**](https://entra.microsoft.com/#view/Microsoft_AAD_Devices/DevicesMenuBlade/~/DeviceSettings/menuId/Devices).
3. Set **Enable Microsoft Entra Local Administrator Password Solution (LAPS)** to **Yes** and select **Save**.

#### Related links

* [Windows Local Administrator Password Solution in Microsoft Entra ID](https://learn.microsoft.com/entra/identity/devices/howto-manage-local-admin-passwords)
* [Microsoft Intune support for Windows LAPS](https://learn.microsoft.com/intune/device-security/laps/overview)

<!--- Results --->
%TestResult%
