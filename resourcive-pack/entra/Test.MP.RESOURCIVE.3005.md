Successful interactive sign-ins in the last week came only from the countries where the organization has staff or customers.

A password that works from a country where nobody works is the plainest sign of a compromised account. Conditional Access can block those countries, but a policy that is report-only, excluded for some users or simply missing will not, and then the sign-in log is where it shows. This check reads the successful interactive sign-ins and groups them by country. Set the `ExpectedCountries` parameter and any sign-in from another country fails the check and is listed by user. Without it the check cannot know which countries are normal, so it lists the countries with counts and the result is **Investigate**.

The sign-in log is slow: one request can take tens of seconds, and a server-side country filter times out after five minutes. The check is long-running. It reads one request per day, newest day first, up to `MaximumSignInsPerDay` records each (default 200), and stops starting new days after `TimeBudgetSeconds` (default 180). It filters by country in PowerShell and shows a table of which days were read in full, partly or not at all, so a quiet result is never taken for full coverage. Business travel and VPN exit points cause legitimate hits; use the list to review, then block unused countries with a Conditional Access location policy.

Licence: Microsoft Entra ID P1 (in Microsoft 365 Business Premium) is needed to read sign-ins through Graph. Reading needs `AuditLog.Read.All` and a role such as Reports Reader, Security Reader or Global Reader.

#### Remediation action

1. For each unexpected user and country, open the sign-in in the [sign-in logs](https://entra.microsoft.com/#view/Microsoft_AAD_IAM/SignInLogsList.ReactView) and check the device, IP address, and result of Conditional Access.
2. If the sign-in was not legitimate, revoke the user's sessions, reset the password and review the account.
3. Create a Conditional Access policy that blocks sign-ins from countries where you have no business presence, using a named location of countries.

#### Related links

* [Block access by location with Conditional Access](https://learn.microsoft.com/entra/identity/conditional-access/policy-block-by-location)
* [Sign-in logs in Microsoft Entra ID](https://learn.microsoft.com/entra/identity/monitoring-health/concept-sign-ins)

<!--- Results --->
%TestResult%
