Every account that holds a privileged Microsoft Entra role, with the roles it holds, listed so that a person can review who has administrative power.

Privileged roles let the holder change security settings, read sensitive data or take over other accounts. Attackers go after these accounts first, so the list should be short, every name on it should be expected, and each account should be used only for administration. This check reads the active and, when the tenant has Entra ID P2 or Governance, the eligible role assignments for the roles Microsoft marks as privileged, and expands role-assignable groups to their members. It never fails. When anyone holds a role the result is **Investigate**, because only the organization can say who should be on the list.

Each account is marked when it is a **guest**, **disabled**, **synced from on-premises Active Directory** (an on-premises compromise then reaches the cloud role), or holds **three or more roles**. Service principals that hold roles are not listed. When the tenant has no Entra ID P2, eligible assignments cannot be read, so accounts that only hold roles through Privileged Identity Management are missing; the result says so. When a group that holds a role cannot be read, its members are missing and the result names the group.

Reading role assignments needs the `RoleManagement.Read.Directory` and `Directory.Read.All` permissions.

#### Remediation action

1. Confirm each account on the list is a person who needs that role today. Remove the roles of anyone who does not.
2. Replace permanent assignments with eligible ones in [Privileged Identity Management](https://entra.microsoft.com/#view/Microsoft_Azure_PIMCommon/CommonMenuBlade/~/quickStart) where the tenant is licensed for it.
3. Move guest, disabled and on-premises synced accounts off privileged roles. Use separate cloud-only accounts for administration.
4. Keep the number of Global Administrators between two and four.

#### Related links

* [Best practices for Microsoft Entra roles](https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices)
* [Privileged roles and permissions in Microsoft Entra ID](https://learn.microsoft.com/entra/identity/role-based-access-control/privileged-roles-permissions)

<!--- Results --->
%TestResult%
