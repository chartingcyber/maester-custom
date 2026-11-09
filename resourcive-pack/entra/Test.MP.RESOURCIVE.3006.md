None of the users who hold privileged Entra roles appears in Have I Been Pwned breach or infostealer log data.

A password in a breach or in infostealer logs can be used by anyone. Infostealer logs matter more: they can contain live session cookies, which skip MFA. This check asks Have I Been Pwned (HIBP) which addresses on your verified domains appear in breaches and, with a Pro subscription, in stealer logs, and joins the result to the people who hold privileged roles. It fails when any of them appears. The number of other exposed addresses is reported.

**This check sends your domain names to a third party and does nothing until you say you may.** Set the `ClientAuthorized` parameter once the organization has authorized it in writing. It also needs:

* An HIBP API key in the `RESOURCIVE_HIBP_API_KEY` environment variable. The API key is never written to the result.
* A Core or Pro subscription for breach search, and Pro for stealer logs.
* Each domain verified in the HIBP dashboard. An unverified domain returns 403 and is reported as not assessed.

Addresses are masked in the result unless `ShowAddresses` is set, so that the result can be shared more widely.

#### Remediation action

1. For each privileged user in the result, reset the password and revoke sessions (**Revoke sessions** in the Entra admin center), and check their sign-in log for unfamiliar sign-ins.
2. For stealer log hits, treat the device the user used as compromised: isolate it and run a full investigation. A password reset alone does not remove a stolen session.
3. Make sure administrators use phishing-resistant MFA (MP.RESOURCIVE.3002) so a stolen password or session is not enough.

#### Related links

* [Have I Been Pwned API v3](https://haveibeenpwned.com/API/v3)
* [Revoke user access in Microsoft Entra ID](https://learn.microsoft.com/entra/identity/users/users-revoke-access)

<!--- Results --->
%TestResult%
