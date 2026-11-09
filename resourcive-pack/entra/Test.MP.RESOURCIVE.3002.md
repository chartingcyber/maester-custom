Every enabled user who holds a privileged Entra role has registered a phishing-resistant authentication method.

A Conditional Access policy that requires phishing-resistant MFA for administrators only works if the administrators have a method that qualifies: a FIDO2 security key, a passkey, Windows Hello for Business, or certificate-based authentication. Without one, they are either locked out when the policy is enforced or the policy is never enforced. This check reads the registration details of each privileged user and lists those without such a method, and those whose only methods are phone, email or one-time passcodes.

CIS 5.2.2.5 and CISA MS.AAD.3.6 check the Conditional Access side. This check checks that the people can comply.

If the tenant has no Entra ID P2, eligible role assignments cannot be read and the result says so. Users with no registration record are listed as not assessed.

Licence: Microsoft Entra ID P1 (included in Microsoft 365 Business Premium) is needed to read registration details. Reading them needs `AuditLog.Read.All` and a role such as Reports Reader, Security Reader or Global Reader.

#### Remediation action

1. Ask each listed administrator to register a passkey or FIDO2 security key at [https://aka.ms/mysecurityinfo](https://aka.ms/mysecurityinfo).
2. In the [Entra admin center](https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/AdminAuthMethods), make sure the passkey (FIDO2) method is enabled for administrators.
3. Then require the built-in **Phishing-resistant MFA** authentication strength for administrator roles with Conditional Access, starting in report-only mode.

#### Related links

* [Conditional Access authentication strengths](https://learn.microsoft.com/entra/identity/authentication/concept-authentication-strengths)
* [Passkeys (FIDO2) in Microsoft Entra ID](https://learn.microsoft.com/entra/identity/authentication/how-to-enable-passkey-fido2)

<!--- Results --->
%TestResult%
