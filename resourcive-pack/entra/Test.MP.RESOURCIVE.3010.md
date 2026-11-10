Every user, application and managed identity that holds a privileged Microsoft Entra role, with the roles it holds, listed so that a person can review who and what has administrative power.

Privileged roles let the holder change security settings, read sensitive data or take over other accounts. Attackers go after these accounts first, so the list should be short, every name on it should be expected, and each account should be used only for administration. This check reads the active and, when the tenant has Entra ID P2 or Governance, the eligible role assignments for the roles Microsoft marks as privileged, and expands role-assignable groups to their members. It never fails. When anyone holds a role the result is **Investigate**, because only the organization can say who should be on the list.

Each account is marked when it is a **guest**, **disabled**, **synced from on-premises Active Directory** (an on-premises compromise then reaches the cloud role), holds **three or more roles**, or is **not MFA capable** (no second method registered; this needs Entra ID P1, and the column shows Unknown without it). Applications and managed identities that hold roles are listed in a second table with who owns them and whether they have client secrets or certificates. They are marked when they belong to another organization (a third-party application), have a client secret, are disabled, or hold three or more roles: an application with a privileged role and a secret that can be stolen or leaked is a common way into a tenant. Roles that an application holds only through a group are not shown. When the tenant has no Entra ID P2, eligible assignments cannot be read, so accounts that only hold roles through Privileged Identity Management are missing; the result says so. When a group that holds a role cannot be read, its members are missing and the result names the group.

Reading role assignments needs the `RoleManagement.Read.Directory` and `Directory.Read.All` permissions. The MFA column also needs `AuditLog.Read.All`, and the application table needs `Application.Read.All`.

#### Remediation action

1. Confirm each account on the list is a person who needs that role today. Remove the roles of anyone who does not.
2. Replace permanent assignments with eligible ones in [Privileged Identity Management](https://entra.microsoft.com/#view/Microsoft_Azure_PIMCommon/CommonMenuBlade/~/quickStart) where the tenant is licensed for it.
3. Move guest, disabled and on-premises synced accounts off privileged roles. Use separate cloud-only accounts for administration.
4. Keep the number of Global Administrators between two and four.
5. For each application, confirm it needs the role. Prefer a certificate or a managed identity to a client secret, and remove roles from applications you do not recognise.

#### Related links

* [Best practices for Microsoft Entra roles](https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices)
* [Privileged roles and permissions in Microsoft Entra ID](https://learn.microsoft.com/entra/identity/role-based-access-control/privileged-roles-permissions)

<!--- Results --->
%TestResult%
