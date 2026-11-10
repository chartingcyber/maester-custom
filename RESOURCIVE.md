# Resourcive assessment

## Quickstart

Start PowerShell (`pwsh`) in the repository folder and run the script from inside it. Use a **fresh** window
(nothing connected to Exchange, Teams or Azure yet). Replace `contoso.com` with the client's domain or tenant ID.

```bash
pwsh
```

First run on a tenant (skips the long-running checks, both Maester's and the pack's: the inbox rule scan, the application permission scan and the Conditional Access What-If scenarios):

```powershell
./Invoke-ResourciveAssessment.ps1 -TenantId contoso.com -SkipLongRunning
```

Full run (adds the long-running checks; roughly 15 to 25 minutes, longer on a larger tenant):

```powershell
./Invoke-ResourciveAssessment.ps1 -TenantId contoso.com
```

The script asks for every Graph permission in one sign-in, then:

1. Opens sign-in prompts for Exchange Online, Security & Compliance and Teams (up to three more).
2. Runs `Install-MtPack`, which shows what the pack reaches and asks you to approve it. Read it and accept.
3. Runs Maester's built-in tests and the pack, and writes the report to `./test-results/contoso.com_20261109-143015/assessment.html` (the folder is named for the tenant and the time the run started).

**Where results go:** `./test-results/<TenantId>_<yyyyMMdd-HHmmss>/`, relative to the folder you run the script from
(the repository folder if you followed the steps above, for example
`<repository>/test-results/contoso.com_20261109-143015/`). The name is the `-TenantId` you typed, then the local date
and time the script started, so every run gets its own folder and repeat runs against the same tenant over time never
overwrite each other. It holds `assessment.html` (open this), `assessment.csv`, `assessment.json`, `assessment.md` and
`assessment-summary.md`. `test-results` is git-ignored, so client data is not committed. Use `-OutputFolder` to choose
the folder yourself (a second run into the same folder would reuse the same file names).

**Running against a different tenant:** use that tenant's domain or ID in `-TenantId`, in a fresh `pwsh` window.
Consent is per tenant, so the permission prompt (or the administrator's approval) happens again, and
`Install-MtPack` asks for approval again. Each run gets its own results folder.

### Sign-in countries

The sign-in country check (3005) fails on any successful sign-in from outside **US and CA** (the first 10 it finds). If
the client does business elsewhere, say so with `-ExpectedCountries`, using two-letter ISO 3166-1 codes
([country code lookup](https://www.iso.org/obp/ui/#search/code/)):

```powershell
./Invoke-ResourciveAssessment.ps1 -TenantId contoso.com -ExpectedCountries GB, IE
```

The check uses Defender advanced hunting, which needs **Entra ID P2** (and the `ThreatHunting.Read.All` permission, already in Maester's default consent). Without P2 it is Investigate and the result gives the steps to check the sign-in log by hand in the Entra admin center. The list replaces the default, so include US or CA if they still apply. The result states which countries were
expected. Sign-ins with no recorded country are not counted. To keep the setting for a client, put it in a config file
instead: `{ "TestSettings": [{ "Id": "MP.RESOURCIVE.3005", "Parameters": { "ExpectedCountries": ["GB", "IE"] } }] }`.

A service you cannot sign in to is not fatal: its checks skip with the reason. To only sign in and check scopes,
without running any tests, add `-GraphOnly`.

What happens at the permission prompt depends on who runs it:

- **A Global Administrator** (or Cloud Application Administrator) sees one consent prompt. Tick "Consent on behalf of
  your organization" and the run continues. Hand the script to an administrator and this is all they do.
- **A Global Reader** cannot approve the permissions. Entra shows "Need admin approval" and, if the tenant has the
  admin consent workflow on, lets you send a request. The script then explains what to do and stops. When the
  administrator has approved it, run the same command again.
- **Need results before approval?** Add `-AllowPartial`. It connects with Maester's own scopes only, so the pack's
  checks that need the extra scopes skip as "Not authorized".

If Graph sign-in says "Method not found", Exchange or Teams was already loaded in that window: open a fresh `pwsh`.

That one command runs the Resourcive M365 assessment against a client tenant, in place of `Connect-Maester`,
`Install-MtPack` and `Invoke-Maester`. The checks are in [`resourcive-pack`](resourcive-pack/README.md) (each check's licence and access needs are listed there); the design is in [`M365 Assessment Toolkit Master Spec.md`](<M365 Assessment Toolkit Master Spec.md>).

## The findings report

`Invoke-Maester` writes `assessment.html`, which lists every check. For a client-ready view, build the findings report from the same results folder:

```powershell
./New-ResourciveReport.ps1 -ResultPath ./test-results/contoso.com_20261109-143015
```

It writes `findings-report.html` (one file, works offline) and `findings-action-list.csv` (ranked failures with blank owner, due date and status columns) into that folder. The report has an overview score, a remediation roadmap (Now, Next, Later), every failure ranked by risk and effort with the fix steps, attack paths, CIS Level 1 and 2, CISA SCuBA, NIST 800-53 and MITRE ATT&CK views, an inventory of privileged accounts, licence gaps, what changed since the previous run of the same tenant, and everything that could not be assessed and why. Skipped, errored and needs-review checks are never counted as passed.

- Email addresses are shown in full. Add `-MaskNames` for a copy that leaves the team (it keeps the first three characters of each address).
- Change the weights, roadmap cut-offs and attack-path mapping in `resourcive-report/risk-model.json`; no code change is needed.
- The previous run is found automatically beside this one (same tenant); use `-ComparePath` to choose one, or `-NoCompare` to skip it.
- Add your own analysis to the first page with `-SummaryPath notes.md`.
- Not verified: the admin inventory and MFA flag need a run with the current pack (checks 3010 and 3011); earlier results show a partial list.

## Why a script instead of the normal commands

`Connect-Maester` requests only Maester's own Graph scopes. The pack declares eight more in `Uses.GraphScopes`, and a
delegated sign-in does not get them unless they are requested. Without them, checks such as BitLocker keys, user and
group queries and the Conditional Access What-If scenarios skip as "Not authorized" and the client has to consent a
second time. The script reads the pack's scopes from `maester-pack.json`, adds them to Maester's own, and signs in
once, so the client approves all 35 scopes in a single prompt. It always loads the cloned module, never a gallery
copy of Maester (which has no pack support and a shorter scope list).

## The process

| Step | Who | What |
| --- | --- | --- |
| 1. Prepare | Assessor | PowerShell 7.4+, clone this repository, install Microsoft's modules (pack README, step 1). Open a fresh `pwsh` in the repository folder. |
| 2. Request | Assessor (Global Reader or better) | `./Invoke-ResourciveAssessment.ps1 -TenantId contoso.com`. All 35 scopes are requested at once. If approval is needed, submit the request Entra offers. |
| 3. Approve | Client Global Administrator | Approve the request in Entra admin center > Enterprise apps > Activity > Admin consent requests (app: *Microsoft Graph Command Line Tools*), or run the same command and tick **Consent on behalf of your organization**. Record who approved and when. |
| 4. Run | Assessor | Run the same command again. It connects Graph, Exchange Online, Security & Compliance and Teams, installs the pack (you review and approve it) and runs everything. |
| 5. Read | Assessor | Open `./test-results/<tenant>_<timestamp>/assessment.html`. Skipped is not passed; each skip names its reason. |

When the account is an administrator or approval already exists, steps 2 to 4 collapse into one run.

Graph never connects with a subset of scopes: either all 35 are granted or the sign-in is blocked, and the script
then stops with instructions (including a consent link for the administrator, which is untested) and returns
`Status = ConsentRequired`. Rerun after approval.

## Options

| Parameter | Effect |
| --- | --- |
| `-GraphOnly` | Graph sign-in and scope check only. Use it to request or grant consent without running. |
| `-AllowPartial` | When approval is blocked, connect with Maester's own scopes and run anyway. |
| `-ConnectOnly` | Connect everything, then stop, leaving the session ready for your own `Invoke-Maester`. |
| `-Service` | Services after Graph. Default `ExchangeOnline, SecurityCompliance, Teams`. |
| `-OutputFolder` | Results folder. Default `./test-results/<TenantId>_<yyyyMMdd-HHmmss>`, one per run. |
| `-SkipLongRunning` | Leave out the long-running checks: Maester's own and the pack's (found from the `LongRunning` flag on each check). |
| `-ExpectedCountries` | Two-letter country codes for the sign-in country check. Default `US, CA`. |
| `-Force` | Run even if a connected token lacks some scopes. |
| `-UseDeviceCode`, `-PackPath` | Device code sign-in; a different pack folder. |
| `-ListScopes` | Print the combined scope list without signing in. |

## Limits

- Delegated consent never gives more than the signed-in role allows. As a Global Reader some checks may still skip as
  "Not authorized" after approval (roles marked "unverified" in the pack README). The request only works where the admin
  consent workflow is on; otherwise the administrator must act directly.
- Consent is delegated and per tenant. It covers the signed-in user's access and creates no app registration.
  Unattended runs would need the certificate-based app in the Master Spec, which is separate work.
- Exchange checks need Exchange roles (View-Only Configuration and View-Only Recipients; Global Reader covers them),
  which no Graph consent grants. Roles marked "unverified" in the pack README still need checking in a tenant.
- `DelegatedAdminRelationship.Read.All` is only useful from a partner tenant. It is requested anyway so the consent
  is identical everywhere; the GDAP check skips with a reason otherwise.
- **Verified once, on the author's own tenant** (an account that could consent): the single Graph sign-in with all 35
  scopes, the Exchange Online, Security & Compliance and Teams connections, pack install, a full run and the report.
- **Not yet verified:** the Global Reader consent-request flow and the administrator consent link; `-SkipLongRunning`
  excluding the pack's long-running checks and `-ExpectedCountries` reaching the check (both added after that run);
  and the sign-in checks 3005 and 3009 on a tenant with Entra ID P2 (their Defender advanced hunting queries have only
  been run against test doubles).
