The changes made to security-relevant settings in the last 30 days, listed so that a person can confirm each was planned.

Attackers who gain administrative access change the controls that would stop them: they exclude themselves from Conditional Access, add an authentication method, grant consent to an application, or assign a role. This check reads the Entra audit log for successful policy, role and application changes and lists who made each one and when. It never fails; when there are changes the result is **Investigate**.

Entra keeps the audit log for 7 days on the Free tier and 30 days with Entra ID P1 or P2, so this list shows the last week or the last month at most. A 90-day change log needs the unified audit log in Microsoft Purview, which this check does not read.

Reading the audit log needs the `AuditLog.Read.All` permission and a role such as Reports Reader, Security Reader or Global Reader.

#### Remediation action

1. For each change you did not expect, open the [audit log](https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuditLogList.ReactView) and find the initiator.
2. If the change was not authorised, revert it and treat the initiating account as compromised.
3. To keep history for longer, send the Entra audit logs to a Log Analytics workspace or storage account with diagnostic settings.

#### Related links

* [Audit logs in Microsoft Entra ID](https://learn.microsoft.com/entra/identity/monitoring-health/concept-audit-logs)
* [Microsoft Entra data retention](https://learn.microsoft.com/entra/identity/monitoring-health/reference-reports-data-retention)

<!--- Results --->
%TestResult%
