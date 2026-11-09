No successful sign-in used a legacy authentication protocol in the recent sign-in log.

Legacy protocols (IMAP, POP, SMTP AUTH, Exchange ActiveSync with basic authentication, and other clients that cannot show an MFA prompt) let a password alone sign in. They are the favourite target of password spray, because MFA never gets a chance to stop it. A Conditional Access policy that blocks them is checked by MT.1009, MT.1010 and CISA MS.AAD.1.1, and MT.1033 simulates sign-ins with the What If API. This check looks at what actually happened: it reads the successful sign-ins whose client is not a browser and not a modern mobile or desktop client, and lists the protocols and users. Any such sign-in fails the check, even when a blocking policy exists, because a policy that is report-only, excluded for the user or scoped to a group will not stop it.

Entra keeps the sign-in log for 30 days with Entra ID P1 or P2, which is also the licence needed to read it through Graph. Reading needs `AuditLog.Read.All` and a role such as Reports Reader, Security Reader or Global Reader.

#### Remediation action

1. For each user and protocol in the result, find the app or device that uses it, and move it to a modern client with modern authentication.
2. Create or fix a Conditional Access policy that blocks legacy authentication for all users, excluding no one except where a documented exception is unavoidable. Use report-only mode first and check the sign-in logs.
3. In Exchange Online, turn off basic authentication for SMTP AUTH where it is not needed: `Set-TransportConfig -SmtpClientAuthenticationDisabled $true`.

#### Related links

* [Block legacy authentication with Conditional Access](https://learn.microsoft.com/entra/identity/conditional-access/policy-block-legacy-authentication)
* [Sign-in logs in Microsoft Entra ID](https://learn.microsoft.com/entra/identity/monitoring-health/concept-sign-ins)

<!--- Results --->
%TestResult%
