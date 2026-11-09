# Resourcive assessment

## Quickstart

Open a **fresh** `pwsh` window (nothing connected to Exchange, Teams or Azure yet) in the repository folder, and
replace `contoso.com` with the client's domain or tenant ID. This is the whole recommended usage:

```powershell
./Invoke-ResourciveAssessment.ps1 -TenantId contoso.com
```

It asks for every permission in one sign-in. What happens next depends on who runs it:

- **A Global Administrator** (or Cloud Application Administrator) sees one consent prompt. Tick "Consent on behalf of
  your organization" and the run continues. Hand the script to an administrator and this is all they do.
- **A Global Reader** cannot approve the permissions. Entra shows "Need admin approval" and, if the tenant has the
  admin consent workflow on, lets you send a request. The script then explains what to do and stops. When the
  administrator has approved it, run the same command again.
- **Need results before approval?** Add `-AllowPartial`. It connects with Maester's own scopes only, so the pack's
  checks that need the extra scopes skip as "Not authorized".

Then open `./test-results/contoso.com/assessment.html`. A full run takes about 25 minutes or more on a larger tenant.

That one command runs the Resourcive M365 assessment against a client tenant, in place of `Connect-Maester`,
`Install-MtPack` and `Invoke-Maester`. The checks are in [`resourcive-pack`](resourcive-pack/README.md) (each check's licence and access needs are listed
there); the design is in [`M365 Assessment Toolkit Master Spec.md`](<M365 Assessment Toolkit Master Spec.md>).

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
| 5. Read | Assessor | Open `./test-results/<tenant>/assessment.html`. Skipped is not passed; each skip names its reason. |

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
| `-OutputFolder` | Results folder. Default `./test-results/<TenantId>`. |
| `-SkipLongRunning` | Leave out the sign-in log and inbox rule scans. |
| `-Force` | Run even if a connected token lacks some scopes. |
| `-UseDeviceCode`, `-PackPath` | Device code sign-in; a different pack folder. |
| `-ListScopes` | Print the combined scope list without signing in. |

## Limits

- Delegated consent never gives more than the signed-in role allows. As a Global Reader some checks may still skip as
  "Not authorized" after approval (for example BitLocker recovery keys). The request only works where the admin consent
  workflow is on; otherwise the administrator must act directly.
- Consent is delegated and per tenant. It covers the signed-in user's access and creates no app registration.
  Unattended runs would need the certificate-based app in the Master Spec, which is separate work.
- Exchange checks need Exchange roles (View-Only Configuration and View-Only Recipients; Global Reader covers them),
  which no Graph consent grants. Roles marked "unverified" in the pack README still need checking in a tenant.
- `DelegatedAdminRelationship.Read.All` is only useful from a partner tenant. It is requested anyway so the consent
  is identical everywhere; the GDAP check skips with a reason otherwise.
- Not yet run against a live tenant. The parse and `-ListScopes` paths are tested; sign-in, the scope check, pack
  install and the run are not.
