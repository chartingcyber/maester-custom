Every Windows device that reports it is encrypted has its BitLocker recovery key stored in Microsoft Entra ID.

BitLocker protects the drive; the recovery key is what gets the user back in after a hardware change or a lockout. If the key is not escrowed, the only way back in is to wipe the device, and the data is lost. This check matches the encrypted managed Windows devices in Intune with the recovery key metadata in Entra ID. It reads only the metadata (key ID, device ID, creation time), never the key itself.

Reading recovery key metadata needs the **BitLockerKey.ReadBasic.All** permission and a role that may read recovery keys (for example Security Reader or Global Reader; confirm in your tenant). Without them the check is skipped with a message that says so.

Licence: Intune Plan 1 (in Microsoft 365 Business Premium).

#### Remediation action

1. In your BitLocker policy in the [Microsoft Intune admin center](https://intune.microsoft.com) (**Endpoint security** > **Disk encryption**), turn on **Save BitLocker recovery information to Microsoft Entra ID** for operating system and fixed drives, and require that backup before encryption starts.
2. For each device in the result, decrypt and re-encrypt, or run `manage-bde -protectors -get C:` and back the key up with `BackupToAAD-BitLockerKeyProtector`.

#### Related links

* [Encrypt Windows devices with BitLocker using Intune](https://learn.microsoft.com/intune/device-security/bitlocker/encrypt-devices)
* [bitlockerRecoveryKey resource type](https://learn.microsoft.com/graph/api/resources/bitlockerrecoverykey)

<!--- Results --->
%TestResult%
