The default cross-tenant access settings do not accept MFA, compliant device or hybrid joined device claims from other organizations.

When a guest from another Microsoft Entra tenant signs in to your tenant, your Conditional Access policies decide whether they must do MFA or use a compliant device. Inbound trust settings let you accept the claims their home tenant made instead. If that trust is on for **all** external tenants, an attacker who controls any Entra tenant (a trial costs nothing) can create a user in it, mark the sign-in as MFA-satisfied and walk past your policy. Trust should be limited to specific partner organizations.

This check fails when any of the three inbound trust settings is on in the default configuration. Partner-specific settings that trust claims are listed so you can confirm they are known partners.

Licence: reading cross-tenant access settings is not documented here as needing a premium licence; some features (B2B direct connect) do. If the read is refused for licensing reasons the check is skipped with a reason.

#### Remediation action

1. In the [Microsoft Entra admin center](https://entra.microsoft.com/#view/Microsoft_AAD_IAM/CrossTenantAccessSettingsBlade), go to **External Identities** > **Cross-tenant access settings** > **Default settings** > **Inbound access** > **Trust settings**.
2. Clear **Trust multifactor authentication from Microsoft Entra tenants**, **Trust compliant devices** and **Trust Microsoft Entra hybrid joined devices**.
3. Add specific organizations under **Organizational settings** and enable trust there only for partners you know.

#### Related links

* [Configure cross-tenant access settings for B2B collaboration](https://learn.microsoft.com/entra/external-id/cross-tenant-access-settings-b2b-collaboration)
* [Overview: Cross-tenant access with Microsoft Entra External ID](https://learn.microsoft.com/entra/external-id/cross-tenant-access-overview)

<!--- Results --->
%TestResult%
