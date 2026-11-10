Every enabled user who holds a privileged Microsoft Entra role is able to complete multifactor authentication.

An administrator account protected only by a password can be taken over by one successful phishing email or password spray, and the attacker then has administrative power. Multifactor authentication stops most of those attacks, but only for accounts that can actually do it. A Conditional Access policy that requires MFA for administrators locks out, or is bypassed for, an administrator who has no usable second method. This check reads the authentication method registration of each enabled privileged user and fails when anyone is not MFA capable: no second method is registered, or the registered methods are blocked by the tenant's authentication methods policy.

Check 3002 asks the next question, whether the methods are phishing resistant. Check 3010 lists who holds the roles. Users with no registration record are listed as not assessed, and when every failing row is of that kind the result is **Investigate**. If the tenant has no Entra ID P2, eligible role assignments cannot be read and the result says so. When a group that holds a role cannot be read, its members are not checked and the result names the group.

Licence: Microsoft Entra ID P1 (included in Microsoft 365 Business Premium) is needed to read registration details. Reading them needs `AuditLog.Read.All` and a role such as Reports Reader, Security Reader or Global Reader.

#### Remediation action

1. Ask each listed administrator to register a method at [My Security Info](https://mysignins.microsoft.com/security-info). Prefer a FIDO2 security key or passkey, or at least Microsoft Authenticator.
2. If a method is registered but not usable, enable that method in [Authentication methods](https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/AdminAuthMethods) for the administrators.
3. Require MFA for administrators with a Conditional Access policy, after confirming every administrator can complete it. Keep emergency access accounts out of the policy and monitored.

#### Related links

* [Plan a Microsoft Entra multifactor authentication deployment](https://learn.microsoft.com/entra/identity/authentication/howto-mfa-getstarted)
* [Require MFA for administrators with Conditional Access](https://learn.microsoft.com/entra/identity/conditional-access/policy-admin-mfa)
* [User registration details report](https://learn.microsoft.com/graph/api/resources/userregistrationdetails)

<!--- Results --->
%TestResult%
