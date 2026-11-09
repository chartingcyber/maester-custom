# Resourcive M365 Assessment

A [Maester Pack](https://maester.dev/docs/packs) (ID `resourcive.m365-assessment`, code `RESOURCIVE`, test IDs
`MP.RESOURCIVE.<n>`) that adds licence-aware checks for Microsoft 365 tenants: a Conditional Access What-If scenario
generator, Intune and Defender endpoint controls, mail persistence and coverage by assignment, and identity gaps.

Every check is read-only. Nothing here changes a tenant.

## Running it

The quickest way is `Invoke-ResourciveAssessment.ps1` at the repository root (see [`RESOURCIVE.md`](../RESOURCIVE.md)),
which does steps 3 to 5 below in one command and asks for every permission in one sign-in. The steps below are the
manual equivalent.

This section takes someone who has never run Maester from nothing to a finished report. It runs every built-in
Maester test and every check in this pack, against one tenant, read-only.

### What you need

- A computer with PowerShell 7.4 or later (`pwsh --version`). On macOS: `brew install powershell`. On Windows:
  `winget install Microsoft.PowerShell`.
- Git, to download this repository (a fork of Maester that contains the pack and the module that can load it). Do not use
  `Install-Module Maester` from the PowerShell Gallery: that version has no pack support, so the pack would not run.
- A work account in the tenant to assess, with at least the **Global Reader** role.
- A **Global Administrator** (or, for delegated permissions, a Cloud Application Administrator) who can approve the
  permission request in step 3. A Global Reader cannot approve it.

### 1. Get the code and install Microsoft's modules (once per computer)

In PowerShell 7 (`pwsh`):

```powershell
git clone <url of this repository> maester-custom
cd maester-custom
Install-Module Microsoft.Graph.Authentication, ExchangeOnlineManagement, MicrosoftTeams -Scope CurrentUser
```

Answer **Y** if PowerShell asks to trust the PowerShell Gallery. These are Microsoft's sign-in and service modules, and
the only things this README installs. Maester itself is not installed: step 2 loads it from the folder you just cloned.

### 2. Load Maester from the cloned folder (every time you start PowerShell)

The window must not have connected to Exchange, Teams, Azure or Graph yet, because Microsoft's sign-in libraries
conflict when Exchange loads before Graph (the failure shows as "Method not found" on the Graph connection). The window
from step 1 is fine if you only ran the commands above in it. Otherwise open a new `pwsh` window and go to the folder:

```powershell
cd maester-custom
Import-Module ./powershell/Maester.psd1 -Force
```

Do not use `Install-Module Maester` from the PowerShell Gallery: that version has no pack support. Stay in this window
for the remaining steps.

### 3. Connect to Microsoft Graph with every permission the tests need

Replace `contoso.com` with the tenant's domain (or its tenant ID) in this step and the next.

```powershell
Connect-MgGraph -TenantId contoso.com -NoWelcome -Scopes ((Get-MtGraphScope) + 'Application.Read.All','BitLockerKey.ReadBasic.All','DelegatedAdminRelationship.Read.All','Device.Read.All','GroupMember.Read.All','RoleManagement.Read.Directory','SecurityEvents.Read.All','User.Read.All')
```

A browser window opens for sign-in. `Get-MtGraphScope` is Maester's own read-only list; the eight scopes added here are the
ones this pack needs on top (`Connect-Maester` cannot add scopes, so this step cannot be skipped).

**If the sign-in says admin approval is required:** a Global Reader cannot grant it. Either of these works:

- A Global Administrator runs the same command on their own computer (steps 1 to 3) and accepts the prompt, ticking
  **Consent on behalf of your organization**. Then you run step 3 again.
- If the tenant has the admin consent request workflow turned on, submit the request when prompted. A Global
  Administrator finds it under Microsoft Entra admin center > Enterprise apps > Activity > Admin consent requests > My
  Pending, for the app *Microsoft Graph Command Line Tools*, and approves it.

Approval is per tenant and must cover these eight scopes even if Maester has been approved there before.

### 4. Connect the other services

```powershell
Connect-Maester -Service ExchangeOnline, SecurityCompliance, Teams -TenantId contoso.com
```

Up to three more sign-in prompts follow. A service you cannot sign in to is not fatal: its tests are reported as
skipped with the reason. Azure and SharePoint are left out on purpose: they need extra modules and, on macOS, Azure
sign-in fails with a broker error. Their tests are skipped.

### 5. Install the pack and run everything

```powershell
Install-MtPack ./resourcive-pack
Invoke-Maester -Pack RESOURCIVE -IncludeLongRunning -OutputFolder ./test-results/contoso -OutputFolderFileName assessment -ExportCsv
```

`Install-MtPack` shows what the pack contains and asks you to approve it; read it and accept. It records the pack and
a digest of its files in `maester-packs.lock.json`, beside the `maester-config.json` that Maester finds from the current
folder, or in `~/.maester` when there is none. `Invoke-Maester` runs the pack only while its files match that lock file,
so run `Install-MtPack` again from the same folder whenever the pack changes. `Invoke-Maester` then runs
the built-in tests and the `RESOURCIVE` pack, including the long-running checks (sign-in log reads and inbox rule
scans). A full run took about 25 minutes on a tenant of roughly 950 users and 3,600 devices; expect longer in a larger tenant,
because the sign-in log is slow and little progress shows for minutes at a time while it is read.

### 6. Read the results

Everything is in `./test-results/contoso`:

| File | What it is |
| --- | --- |
| `assessment.html` | The report to open in a browser. |
| `assessment.csv` | One row per test, for sorting in a spreadsheet. |
| `assessment.json` and `assessment.md` | The same data for tools and for reading as text. |

Results are **Passed**, **Failed**, **Investigate** (a person must decide), **Skipped** (not assessed, and the reason is
given, for example "Not licensed" or "Not authorized") and **Error**. A skip is not a pass. The report contains tenant
data about the client; store and share it accordingly and do not commit it.

### Running part of the pack

```powershell
# One or more checks by ID, with a parameter (a check named by exact ID runs even if it is long-running):
Invoke-MtTest -Path ./resourcive-pack -Id MP.RESOURCIVE.3005 -Parameter @{ ExpectedCountries = 'US', 'CA' }

# The pack alone, without the built-in tests:
Invoke-Maester -Pack RESOURCIVE -SkipBuiltIn -IncludeLongRunning -OutputFolder ./test-results/contoso-pack
```

Checks marked *long-running* run with `Invoke-Maester` only when `-IncludeLongRunning` is given.

### Parameters worth setting

- `ExpectedCountries` (3005): two-letter ISO 3166-1 codes of the countries where sign-ins are expected. **Default: US and
  CA.** The check fails on any successful interactive sign-in from another country and stops at the first 10 it finds
  (`MaximumMatches`). Change it with `./Invoke-ResourciveAssessment.ps1 -TenantId <tenant> -ExpectedCountries GB, IE`, or
  per client in a config file: `{ "TestSettings": [{ "Id": "MP.RESOURCIVE.3005", "Parameters": { "ExpectedCountries":
  ["GB", "IE"] } }] }`, or with `-Parameter @{ ExpectedCountries = 'GB', 'IE' }` on `Invoke-MtTest`. The list replaces the
  default, so keep US or CA in it if they still apply. Look codes up at
  [iso.org](https://www.iso.org/obp/ui/#search/code/).
- `ClientAuthorized` (3006): the Have I Been Pwned check sends the tenant's domain names to a third party and is skipped
  until the organization's written authorization is recorded; it also needs an API key in `RESOURCIVE_HIBP_API_KEY`.
- `PartnerExportPath` (3004): GDAP relationships are visible only from the partner tenant; give a JSON export or run it
  from there.

### If something goes wrong

| Symptom | Fix |
| --- | --- |
| "Method not found" when connecting Graph | Close PowerShell, start a fresh `pwsh`, import the module, and connect Graph before anything else. |
| `Install-MtPack` or `-Pack RESOURCIVE` is not recognized | The gallery Maester was loaded. Start a fresh `pwsh` and run the `Import-Module ./powershell/Maester.psd1 -Force` line again. |
| `Invoke-Maester` refuses the pack, or the results look like an older version | Run `Install-MtPack ./resourcive-pack` again, then rerun. |
| Many checks skipped as "Not authorized" | A scope in step 3 was not approved. Have the administrator approve it and reconnect. |
| Many checks skipped as "Not licensed" | The tenant lacks that product (for example Entra ID P2). Expected on Business Premium; see the licence table below. |

Unit tests (Graph and Exchange stubbed, no tenant needed): `Invoke-Pester ./resourcive-unit-tests`.
Pack validation: `Test-MtPack ./resourcive-pack`.

## How licences are handled

Each check declares `License` (Microsoft service plan names). The engine skips a check whose licence the tenant
lacks, with reason `LicenseNotFound`. A second line of defence runs inside the check, for runs where the engine's
licence gate is off or the licences could not be read: `Assert-ResLicense` skips the check with a reason that
starts with **"Not licensed:"**, and a Graph licence error or a 401 or 403 is turned into a skip that starts with
**"Not licensed:"** or **"Not authorized:"** and names the permission or role to add. A check never reports Pass because
it could not read its data; unreadable parts are reported as **Not assessed** (Investigate or Skipped).

| Product | Service plan names used | In Microsoft 365 Business Premium |
| --- | --- | --- |
| Entra ID P1 (Conditional Access, sign-in logs, registration details) | `AAD_PREMIUM` | Yes |
| Entra ID P2 (risk-based CA, PIM) | `AAD_PREMIUM_P2`, `Entra_Identity_Governance` | No (Defender Suite add-on adds it) |
| Intune Plan 1 | `INTUNE_A` (and variants) | Yes |
| Defender for Business / Endpoint | `MDE_SMB`, `MDE_LITE`, `WINDEFATP` | Yes (`MDE_SMB`) |
| Defender for Office 365 Plan 1 | `ATP_ENTERPRISE` | Yes |
| Exchange Online mailbox | `EXCHANGE_S_STANDARD` and variants | Yes |

Source: Microsoft Learn, "Product names and service plan identifiers for licensing" and the licensing pages of each
product (researched 2026-10-27).

## The checks

Access beyond Global Reader is in the last column. "Permission" is a Microsoft Graph permission to consent to.
Roles marked (unverified) were not confirmed against a tenant and need testing.

| ID | Check | Severity | Licence | Needs beyond Global Reader |
| --- | --- | --- | --- | --- |
| 1001 | Windows LAPS enabled in Entra | Medium | none | Policy.Read.All |
| 1002 | Intune LAPS policy assigned to all devices, rotation within limit (an unset age counts as the Windows default of 30 days) | Medium | Intune P1 | DeviceManagementConfiguration.Read.All |
| 1003 | USB and removable storage blocked on all Windows devices | Medium | Intune P1 | DeviceManagementConfiguration.Read.All |
| 1004 | Untrusted scripts blocked (ASR script rules or App Control) | High | Intune P1 + Defender for Business/Endpoint | DeviceManagementConfiguration.Read.All |
| 1005 | Every ASR rule in Block mode for all devices | High | Intune P1 + Defender for Business/Endpoint | DeviceManagementConfiguration.Read.All |
| 1006 | Defender Antivirus protections enforced by policy | High | Intune P1 | DeviceManagementConfiguration.Read.All |
| 1007 | Device state: real-time, tamper protection, signatures | High | Intune P1 | DeviceManagementManagedDevices.Read.All |
| 1008 | BitLocker policy coverage and device encryption state. Devices that have not synced for 30 days are left out; if none is left the result is Investigate, never a pass | High | Intune P1 | both of the above |
| 1009 | BitLocker recovery key escrowed in Entra | Medium | Intune P1 | BitLockerKey.ReadBasic.All and Global Reader, Security Reader, Security Administrator, Helpdesk Administrator, Intune Administrator or Cloud Device Administrator (Microsoft's list for the recovery key list call; the call returned no error as Global Administrator, but no key has been read yet) |
| 1010 | Windows compliance policies reach all devices and block | High | Intune P1 | DeviceManagementConfiguration.Read.All |
| 1011 | Conditional Access requires a compliant device (scope) | High | Entra P1 + Intune P1 | Policy.Read.All |
| 1012 | No unmanaged joined device signed in recently | Medium | none | Device.Read.All |
| 1013 | Device registration quota and MFA at join | High | none (CA part needs Entra P1) | Policy.Read.All |
| 2001 | Safe Links and Safe Attachments reach every mailbox | High | Defender for Office P1 | User.Read.All; Exchange role to read protection rules (unverified) |
| 2002 | Privileged users covered by Strict preset | Medium | Defender for Office P1 | RoleManagement.Read.Directory, User.Read.All |
| 2003 | No mailbox forwards externally | High | Exchange | none expected |
| 2004 | Auto-forwarding blocked tenant-wide | High | Exchange | none expected |
| 2005 | Inbox rules: external forward, hidden mail (long-running) | High | Exchange | Exchange role such as View-Only Recipients or Mail Recipients (unverified) |
| 2006 | Transport rules do not copy mail externally | High | Exchange | none expected |
| 2007 | Inbound connectors restricted; outbound connectors listed | High | Exchange | none expected |
| 3001 | Recent security changes in the audit log (Info; changes made by the account running the assessment are marked *) | Info | none | AuditLog.Read.All |
| 3002 | Privileged users have a phishing-resistant method registered | High | Entra P1 | AuditLog.Read.All, RoleManagement.Read.Directory |
| 3003 | Default cross-tenant settings do not trust external MFA/device claims | High | none (unverified) | Policy.Read.All |
| 3004 | GDAP relationships with privileged roles | Medium | none | **Partner side only** (DelegatedAdminRelationship.Read.All) or a partner export file |
| 3005 | Successful sign-ins only from expected countries, default US and CA (long-running) | Medium | Entra P1 | AuditLog.Read.All |
| 3006 | HIBP breach and stealer log exposure of privileged users | High | HIBP Core/Pro | HIBP API key in `RESOURCIVE_HIBP_API_KEY`; written client authorization |
| 3007 | Secure Score gaps (Info) | Info | none | SecurityEvents.Read.All |
| 3008 | Broad Graph application permissions on third-party or owner-less apps (long-running) | High | none | Application.Read.All, Directory.Read.All |
| 3009 | Successful legacy-protocol sign-ins, interactive and non-interactive (long-running) | High | Entra P1 | AuditLog.Read.All |
| CA | Conditional Access What-If scenarios (family, long-running) | per row | Entra P1 (risk axes need P2) | Policy.Read.All or Policy.Read.ConditionalAccess, User.Read.All, GroupMember.Read.All, RoleManagement.Read.Directory |

### Conditional Access What-If family (`MP.RESOURCIVE.CA`)

See `conditional-access/Test.MP.RESOURCIVE.CA.md` for how personas and scenarios are chosen, how outcomes are
classified, the default expectations, the desired-state file and the `Resourcive.CA.*` settings.

## What this pack does not duplicate

Maester already ships these, so this pack points to them instead of repeating them:

| Topic | Existing checks |
| --- | --- |
| SPF, DKIM, DMARC per domain | CISA.MS.EXO.2.2, 3.1, 4.1 to 4.3; CIS.M365.2.1.9; MT.1182; ORCA.108, 235, 244 |
| Audit logging on, retention | MT.1172; CIS.M365.3.1.1; CISA.MS.EXO.13.1, 17.1 to 17.3 |
| Standing Global Admins, PIM use | MT.1030, 1031, 1032; CISA.MS.AAD.7.x |
| Users MFA capable | CIS.M365.5.2.3.4 |
| App consent settings | CIS.M365.5.1.5.x; CISA.MS.AAD.5.x; EIDSCA.AP, CP, CR |
| Emergency access accounts | MT.1005, 1034, 1191 |
| Who may join devices, join MFA conflicts | MT.1070, MT.1061 |
| Devices with no compliance policy | MT.1054; CIS.M365.4.1 |
| BitLocker settings quality | MT.1123 |
| App Control exists and enforces | MT.1179 |
| Spam bypass by transport rule | MT.1043 |
| Legacy authentication blocked by policy | MT.1009, 1010, 1033; CISA.MS.AAD.1.1; CIS.M365.5.2.2.3 |
| Smart lockout settings | EIDSCA.PR05, PR06; CIS.M365.5.2.3.8, 5.2.3.9 |

Not assessed by any check, because tenant settings cannot show it: PowerShell Constrained Language Mode (a device
setting; 1004 says so in every result), and Intune Device Control rule entries (1003 lists the profiles and returns
Investigate instead of guessing).

## Known limits

The pack has run against two real tenants. The first full run found bugs that the unit tests (Graph and Exchange stubbed)
had hidden, since fixed and covered by tests that use the response shapes Graph returns: a nested `$expand` that Graph rejected with
a 400 (now split into one expand per request), `-DisablePaging` returning the raw response instead of the rows, and an
empty privileged-user list, most likely because `isPrivileged` is returned only by the beta role definitions endpoint (the
fix has not been confirmed in a tenant yet). Still to confirm: the settings catalog definition IDs (which Microsoft can
rename) and the roles marked "unverified" above.

The sign-in log is slow (tens of seconds for a request). The sign-in checks (3005, 3009) therefore ask Graph for the
matching sign-ins only, in one request over the 7 days, and stop at the first 10 matches. If Graph refuses that filter or
it times out, they read one small request per day and filter in PowerShell; any day not read in full is listed, and a
result with no matches is then Investigate, never a pass. 3009 searches the beta sign-in log for non-interactive
sign-ins as well, because legacy protocols usually sign in non-interactively and the v1.0 log does not return those;
if the beta log cannot be read it says so and cannot pass. Neither the server-side filters nor the beta event filter have
been run against a tenant yet. Secure Score (3007) needs `SecurityEvents.Read.All`, which
Maester's default Graph consent does not include: consent to it when you connect.
