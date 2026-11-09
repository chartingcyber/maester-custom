Delegated admin (GDAP) relationships with a managed service provider do not grant highly privileged roles for a long period.

A GDAP relationship lets a partner (an MSP) administer your tenant with the roles you approved, for the time you approved. A relationship that grants Global Administrator, Privileged Role Administrator or a similar role, for a year or two, is a standing path into your tenant through someone else's accounts. This check flags active relationships that grant a highly privileged role, and those with such a role that run longer than `MaximumDays`.

**This is normally not readable from the customer tenant.** GDAP relationships are visible from the partner side. Pass `PartnerExportPath`, a JSON export that the MSP produces (for example `Get-MgTenantRelationshipDelegatedAdminRelationship | ConvertTo-Json -Depth 10`), or run the check from the partner tenant with `DelegatedAdminRelationship.Read.All`. Without either, the check is skipped with a reason that says so; it is never reported as passing.

#### Remediation action

1. Ask the partner to replace broad roles with the least privileged roles their service needs, and to use Just-in-time access (PIM for groups) for the roles they rarely use.
2. Shorten the relationship duration, or terminate relationships you no longer use, in the [Microsoft 365 admin center](https://admin.microsoft.com/#/partners).
3. Review sign-in logs for the partner's activity.

#### Related links

* [Granular delegated admin privileges (GDAP) introduction](https://learn.microsoft.com/partner-center/customers/gdap-introduction)
* [delegatedAdminRelationship resource type](https://learn.microsoft.com/graph/api/resources/delegatedadminrelationship)

<!--- Results --->
%TestResult%
