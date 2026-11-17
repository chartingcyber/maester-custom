No privileged Microsoft Entra user is excluded from an enforced Conditional Access policy that targets them.

A Conditional Access exclusion is usually made for a good reason: a service account that cannot do MFA, an administrator who was locked out, a pilot group. Over time the exclusions pile up, and the accounts with the most power are the ones most likely to be on them. An administrator who is excluded from the MFA policy, the legacy authentication block or the device requirement escapes exactly the control that policy applies, so an attacker who takes over that account meets none of those controls. This check reads the enforced policies that grant, block or restrict access and, for each enabled user who holds a privileged role, works out which policies target them and which of those also exclude them, by user, by group or by role.

Emergency access (break glass) accounts are excluded from policies on purpose, so that a policy mistake cannot lock everyone out. This check lists them but does not exempt them: when they are the only privileged users excluded, the result is **Investigate** so a person confirms the exclusions are the intended ones and that the accounts are monitored. Set the `EmergencyAccessAccounts` setting so they are recognised. Check 3011 does the same for MFA.

Report-only and disabled policies are not counted, because they control nothing yet. A guest is matched by user type, not by the specific guest type a policy names. If the tenant has no Entra ID P2, eligible role assignments cannot be read and the result says so. When a group that holds a role cannot be read, its members are not checked.

Licence: Microsoft Entra ID P1 (included in Microsoft 365 Business Premium). Reading the policies, roles and group members needs `Policy.Read.All`, `RoleManagement.Read.Directory`, `GroupMember.Read.All` and `User.Read.All`; Global Reader covers these.

#### Remediation action

1. For each listed administrator, open the policy named in the table and remove the exclusion unless there is a documented reason for it.
2. Where an administrator cannot meet a policy's requirement (for example no MFA method), fix the requirement, not the exclusion: register a method, or enrol the device.
3. Keep exclusions for emergency access accounts only, document them, exclude them from every policy the same way, and monitor their sign-ins.
4. Prefer excluding a small, named group over individual users, and review that group's members on a schedule.

#### Related links

* [Conditional Access: Users, groups, agents, and workload identities](https://learn.microsoft.com/entra/identity/conditional-access/concept-conditional-access-users-groups)
* [Manage emergency access accounts in Microsoft Entra ID](https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access)
* [Conditional Access policy for administrators](https://learn.microsoft.com/entra/identity/conditional-access/policy-admin-mfa)

<!--- Results --->
%TestResult%
