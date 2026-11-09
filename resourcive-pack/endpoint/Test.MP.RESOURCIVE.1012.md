No device that is joined to the directory but not managed by Intune has signed in recently.

A device joined to Entra ID gets the user's tokens and, often, single sign-on to everything. If it is not managed it has none of the controls in this assessment: no compliance policy, no encryption policy, no attack surface reduction rules. Devices that are only registered (personal devices) are left out by default because they are expected to be unmanaged. Use the `IncludeRegistered` parameter to count them too. Printers and computer accounts (names ending in `$`) are left out because Intune cannot manage them. Hybrid joined devices are listed separately, because Configuration Manager or Group Policy may manage them where Entra cannot see it. When only hybrid devices are unmanaged the result is **Investigate**.

This check reads the Entra device list. It needs no Intune licence, but it is most useful where Intune is the intended management tool.

#### Remediation action

1. Review each device listed in the [Entra devices list](https://entra.microsoft.com/#view/Microsoft_AAD_Devices/DevicesMenuBlade/~/Devices).
2. Enrol the device in Intune, or delete the stale device object if it is gone.
3. To stop new unmanaged joins, require MFA for device join with Conditional Access and restrict who may join devices (see MP.RESOURCIVE.1013).

#### Related links

* [Manage stale devices in Microsoft Entra ID](https://learn.microsoft.com/entra/identity/devices/manage-stale-devices)
* [Microsoft Entra joined devices](https://learn.microsoft.com/entra/identity/devices/concept-directory-join)

<!--- Results --->
%TestResult%
