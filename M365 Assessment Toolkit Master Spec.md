# M365 Assessment Toolkit Master Spec

Oct 27, 2026 · @Nerd

This spec defines a repeatable, tenant-settings-only Microsoft 365 security assessment for Entra, Intune, Defender and Exchange Online, built on a pinned Maester run plus custom collectors, a rules layer and a takeaways report.

## Scope and non-scope

The assessment answers one question: which technical tenant settings let an attacker in, persist, or move, and which controls are missing, partial, or audit-only. It is not a CIS scan with a cover page.

**In scope (technical tenant settings only)**

- Entra ID: Conditional Access, roles and PIM, authentication methods, app registrations and consent, cross-tenant access, device registration, sign-in behavior.
- Intune: compliance, configuration, ASR, device control, storage and script restrictions, App Control, LAPS, BitLocker, enrollment.
- Defender: Defender for Office 365 policy coverage by assignment, endpoint AV and tamper settings, Secure Score gaps.
- Exchange Online: forwarding, inbox rules, transport rules, email authentication (SPF, DKIM, DMARC), audit and logging settings.
- External exposure facts: Have I Been Pwned domain breach and stealer log checks joined to tenant identities.

**Out of scope (never collected, never scored)**

- Interviews, process review, policy documents, social engineering or help desk readiness.
- On-premises Active Directory, network, and endpoint state outside Intune and Defender settings, unless a client adds them as a separate paid module.
- Penetration testing or any change to tenant configuration. The run is read-only.

**Principle:** a failing control is a control conversation, not a verdict. Every finding carries an outcome state so clients can accept, defer, or dispute it.

## Architecture and run flow

The run is a six-stage pipeline. Stages 1 to 3 collect, stage 4 tests, stages 5 and 6 interpret. Every stage writes files to a run folder so a collect-only MSP run can be handed over and replayed.

1. **Preflight and coverage manifest.** Confirm tenant ID, runner identity and role, licenses present, scopes granted, module versions. Output: `manifest.json` listing every module as Ready, Limited (with reason), or Blocked. Anything not collectable is reported as Not assessed, never as Pass.
2. **Snapshot.** Pull tenant state through Microsoft Graph and Exchange Online PowerShell into JSON: CA policies, role assignments and eligibility, auth method registrations, apps and service principals, devices, Intune policies, Defender and mail policies, cross-tenant settings. Each file carries an as-of timestamp and a SHA-256 hash.
3. **CA scenario generator.** Builds identity equivalence classes from policy include and exclude signatures, picks one representative per class plus every privileged user, builds axes from what the tenant actually uses (apps, client types, platforms, locations, risk), and calls the Graph What-If endpoint (`POST /beta/identity/conditionalAccess/evaluate`) with caching and throttling. Output: scenario results plus generated Maester custom tests.
4. **Maester run.** Pinned stable 2.x with CIS, CISA, EIDSCA, MT, ORCA and the generated custom tests. Output: standard Maester artifacts.
5. **Rules layer and fact tables.** Deterministic code joins the snapshot, fact tables and Maester results, applies severity rules, outcome states and license gates, and maps each result to a finding. No model is involved here.
6. **Takeaways report.** A self-contained HTML page (no CDN calls) with the CA heatmap, privileged-user table, endpoint control matrix, top findings by attacker outcome, and the coverage matrix. Optional narrative step: a Claude skill drafts prose from the structured findings only, after pseudonymization.

**Design rules that apply to every stage**

- Organize findings by attacker outcome (for example, takeover of an admin account), with CIS and SCuBA IDs as tags and an appendix.
- Pass and fail are decided from the snapshot by code. A model may explain a finding, never decide it.
- Mark every figure with its as-of time. Keep run metadata (tenant ID, runner and role, versions, timestamps, scopes, file hashes) with the output.
- Pseudonymize user and device identifiers before any model step.

## Data model

Three layers: raw snapshot, fact tables (information only, no severity), and findings (rules applied). Facts feed rules, so every finding can be traced to rows.

**Fact tables**

| Table | Contents | Source |
| --- | --- | --- |
| `admins` | Every user, group and service principal holding an active or eligible directory role, with role, assignment type, last sign-in | Graph role assignment and eligibility schedule instances |
| `global_admins` | Subset of `admins` holding Global Administrator, including nested group paths | Same |
| `mfa_registration` | Per user: methods registered, default method, phishing-resistant yes or no, passwordless yes or no | `reports/authenticationMethods/userRegistrationDetails` |
| `users_no_mfa` | Enabled users with no usable second factor registered | Derived from `mfa_registration` |
| `ca_policies` | Normalized CA policies with state (enforced, report-only, disabled), scope, grant controls | Graph CA policies |
| `apps_consent` | App registrations, service principals, delegated and application permissions, credential expiry, consent type | Graph |
| `partners_xtenant` | Cross-tenant access defaults and per-partner settings, delegated admin relationships | `policies/crossTenantAccessPolicy`, delegatedAdminRelationships |
| `devices` | Registered, joined and managed devices, compliance, owner, last sign-in | Graph, Intune |
| `mail_rules_fwd` | Mailbox forwarding, inbox rules that forward or delete, transport rules, connectors | Exchange Online PowerShell |
| `hibp_exposure` | Domain breach and stealer log hits by email address | Have I Been Pwned |

**Joined privileged-user table.** One row per privileged identity: roles (active and eligible), cloud-only or synced, MFA methods, phishing-resistant flag, last sign-in, CA coverage class, HIBP exposure. This table is the first page of the report.

**Finding schema**

| Field | Values |
| --- | --- |
| `id` | Stable finding ID, for example `ID-CA-001` |
| `outcome` | Fail, Accepted by client, Not applicable (license), Manual, Not assessed, Pass |
| `severity` | Critical, High, Medium, Low, Info (see severity rules in each module) |
| `attacker_outcome` | The result an attacker gains, for example Admin takeover, Persistence, Mail exfiltration |
| `evidence` | Fact table rows or snapshot file and hash |
| `license_gate` | License required to remediate, so unlicensed gaps show as a decision, not a defect |
| `remediation` | Control to change, blockers, safe rollout path (report-only first) |
| `tags` | CIS, SCuBA, EIDSCA and test IDs |

**Mapping file.** One table maps each Maester test ID and each custom rule to its scenario, severity tier, license gate, finding text and tags. Tests that are not mapped appear in an appendix so nothing is silently dropped. A stored previous run enables quarter-over-quarter diffs by finding ID.

## Identity and access modules

Each module lists data source, access needed, severity rules and outputs. Access names are Graph permissions or roles to confirm in preflight; Global Reader reads most of this, but `userRegistrationDetails` and some report endpoints must be tested per tenant (unverified).

| Module | Data source and access | Severity rules (examples) | Output |
| --- | --- | --- | --- |
| CA coverage engine | CA policies and What-If evaluate (`Policy.Read.All`, `Policy.Read.ConditionalAccess`, beta) | Critical: any privileged user with no MFA or no block outcome in a modeled scenario. High: legacy auth reachable for any enabled user. Medium: coverage depends on report-only policies. | Heatmap (identity class by app and client type), outcome per scenario, per-persona assertions, report-only separated from enforced |
| Privilege and PIM | Role assignment and eligibility schedule instances (Global Reader) | Critical: standing Global Admin count above agreed cap, or any Global Admin without phishing-resistant MFA. High: permanent assignments where PIM is licensed, cloud-only break-glass missing. | Privileged-user table, standing vs eligible, role counts |
| MFA and authentication methods | `userRegistrationDetails` (`AuditLog.Read.All`), authentication methods policy | High: enabled users with no MFA registered. Medium: SMS or voice as only factor. Info: passkey and FIDO2 adoption. | `users_no_mfa`, method distribution, phishing-resistant gap list |
| Apps and consent | App registrations, service principals, consent grants (Graph) | High: broad application permissions (for example `Mail.ReadWrite`, `Directory.ReadWrite.All`) on multi-tenant or unowned apps, user consent open. Medium: expired or long-lived secrets. | `apps_consent`, risky permission list, owner-less apps |
| Legacy auth and sign-in behavior | Sign-in logs through Defender advanced hunting or Graph (KQL via `Invoke-MtGraphSecurityQuery`) | High: successful legacy protocol sign-ins in last 30 days. Medium: sign-ins from countries with no business presence. | Legacy auth users and clients, geography summary |
| Cross-tenant access and partners | `policies/crossTenantAccessPolicy` (`Policy.Read.All`), delegated admin relationships (`DelegatedAdminRelationship.Read.All`, partner side) | High: inbound trust of MFA and device claims from all tenants by default. Medium: stale GDAP relationships with high roles. | `partners_xtenant`, relationship list (GDAP needs MSP Partner Center export) |
| Device registration | Device registration policy, Entra devices (Graph) | High: any user can register unlimited devices with no MFA at join. Medium: unmanaged devices with recent sign-ins. | `devices`, rogue registration list |

**CA coverage method.** Sampling alone misses edge cases, so the engine groups users by the exact set of policies that include or exclude them, tests one representative per group, and tests every privileged user individually. Results fold into one of: Block, phishing-resistant strength, MFA, device required, no control, Not assessed. What-If gaps (conditions the endpoint cannot evaluate) are listed, not guessed. Output is also exposed as a data-driven custom Maester test so results land in the standard artifacts.

## Mail, device and endpoint modules

**Endpoint control matrix.** Each control is reported per assignment scope with a status: Enforced, Audit-only, Partial scope, Conflicting, Not configured, Not applicable. Maester MT.1178 covers only three Standard Protection ASR rules, so the script rules and USB rule need custom tests.

| Control | Where it is set | What counts as Enforced |
| --- | --- | --- |
| Block USB mass storage | Defender Device Control profile, Storage CSP `RemovableDiskDenyWriteAccess`, ASR USB rule | Deny policy assigned to all in-scope Windows devices, not Audit |
| Block untrusted scripts | ASR script rules, App Control for Business, Constrained Language Mode | Rule in Block mode, or App Control enforced for script hosts |
| ASR rules | Intune endpoint security profile | Each rule in Block, with exclusions listed |
| Defender AV and tamper protection | Intune and Defender settings | Real-time, cloud protection and tamper protection on |
| LAPS | Intune LAPS policy | Policy assigned, backup to Entra or AD, password age set |
| BitLocker | Intune disk encryption | Required on all Windows devices, recovery key escrow on |
| Compliance and CA link | Compliance policies, CA device grant | Compliance policy assigned, CA requires compliant device for in-scope apps |

Reference implementations to check against: `msec` `Get-MsecIntuneAsrRule` and TenantPulse (unverified fit, review before reuse).

**Defender for Office coverage by assignment.** Policies existing is not coverage. Read Safe Links, Safe Attachments and anti-phishing rules with `Get-EOPProtectionPolicyRule`, `Get-ATPProtectionPolicyRule` and `Get-ConfigAnalyzerPolicyRecommendation -IsAppliedToDisabled`, then compute which users and domains each policy actually reaches. Severity: High if any enabled user is outside Safe Links and Safe Attachments, Medium if only Standard rather than Strict for privileged users.

**Mail and persistence**

- Inbox rules, mailbox forwarding and transport rules: High for any external auto-forward or hidden delete rule on a privileged user.
- Email authentication: SPF, DKIM and DMARC per accepted domain. High: no DMARC or `p=none` on a sending domain.
- Audit and logging: unified audit log on, mailbox audit on, retention length. High if audit is off.
- Change log: audit log events for policy and role changes in the last 90 days, listed for the report.

**Have I Been Pwned.** Domain breach, stealer logs by email domain, and website domain, joined to the privileged-user table, MFA state and last sign-in. Preconditions: client authorizes the check, domain is verified, subscription status is confirmed. Pseudonymize addresses before any model step. Severity: Critical if a privileged user appears in stealer logs with a session newer than the last password change.

**Optional modules (priced separately):** Power Platform and connectors, mail flow, Azure subscription bridge, hybrid identity.

## Baselines and completeness audit

Baselines are inputs, not the product. Every Maester test and custom rule maps to a finding and a tag, and a completeness check lists what no baseline covers.

| Source | Role in this toolkit | Notes |
| --- | --- | --- |
| CIS Microsoft 365 Foundations v7.0.0 (released May 19, 2026) | Tag and appendix. Used to answer "which benchmark item is this" | Does not answer whether the tenant is secure |
| CISA SCuBA baselines | Tag and appendix, primarily through Maester CISA tests | Tenable audit files exist for SCuBA v1.5.0 (3/22/2025) |
| EIDSCA | Entra settings coverage through Maester | Tag |
| ORCA | Defender for Office checks through Maester | Supplemented by coverage by assignment |
| Microsoft Zero Trust Assessment | Optional cross-check, not part of the default run | Hundreds of tests, first run needs Global Admin consent, later runs Global Reader, can exceed 24 hours on large tenants, scopable by pillar or test ID |
| Secure Score control profiles | Gap mapping | `SecurityEvents.Read.All` |

**Completeness audit (run once per toolkit release).** Export the full Maester test inventory with `Get-MtTestInventory`, then report three lists: tests mapped to a finding, tests intentionally excluded with a reason, and tests unmapped. Do the same for each CIS v7 item and SCuBA control. A release is not done while unmapped items remain.

**Version pinning.** Pin a stable Maester 2.x for client work. Maester 3.0 is in preview (PowerShell 7.4 or later, native `Test.<ID>.ps1` format, Pester custom tests run from a `Custom` folder). Evaluate 3.0 in the lab tenant only, and re-verify details against the current release notes before moving (unverified).

## Access and consent

Global Reader is enough for most reads but not all, so preflight decides what runs. Anything blocked is listed as Not assessed with the access needed to unblock it.

- **Authentication.** Certificate-based app authentication with a per-client app registration, read-only Graph permissions listed in the engagement letter, and Exchange Online access through a read-only role. Avoid client secrets. First-run admin consent is a client Global Administrator action; record who consented and when.
- **Runner role.** Document the runner identity and role in the manifest. A Global Reader user covers role and policy reads. Test `userRegistrationDetails`, Intune reads and Defender advanced hunting under Global Reader in the lab tenant before promising them (unverified).
- **MSP collect-only mode.** The MSP runs stages 1 and 2 only and returns the snapshot folder with file hashes. Analysis happens on our side. No credentials leave the client tenant.
- **Cleanup.** After the engagement, remove the app registration, certificates and consent grants, and confirm removal in the manifest.
- **GDAP.** Delegated admin relationships are visible only from the partner side, so GDAP findings need a Partner Center export from the MSP.
- **Data handling.** Snapshots hold personal data. Encrypt at rest, restrict to the engagement, delete per the agreed retention period, and pseudonymize before any model step. HIBP checks need written client authorization.

## License and legal notes

Licenses decide what can be reused in a paid engagement. Confirm each against the current repository text before first client use.

| Component | License or terms | Implication |
| --- | --- | --- |
| Maester | Open source (confirm current license text) | Run in client work; pin version |
| Conditional Access Validator | CC BY-NC-SA 4.0; commercial use needs written permission | Do not use commercially without permission. Reimplement the idea, do not copy code |
| CA Insight | GPL-3.0 | Use as a validation comparator only. Copying code into the toolkit brings GPL terms |
| CA Gap Analyzer | MIT | Safe to reference and adapt with attribution |
| PSGuerrilla `Test-GuerrillaConditionalAccess`, CaOutcome, idPowerApp | Not verified | Read for ideas only until licenses are checked |
| Tenable Nessus Pro | About $4,790 per year list; CIS M365 v7.0.0 L1 E3 audit (about 100 items) and SCuBA v1.5.0 audits | Terms for recurring client scans are unverified. Pay only if it reduces interpretation time |
| Microsoft Zero Trust Assessment | Free, open source | Optional cross-check |

Attribute every adapted idea in the toolkit README and keep a third-party notices file.

## Validation plan

The toolkit is trusted only after it finds planted problems in a lab tenant and agrees with independent tools.

1. **Lab tenant with planted gaps.** Build a developer or trial tenant with a known list of defects: a CA policy that excludes a group, a privileged user with SMS only, legacy auth allowed, an over-permissioned app, an external auto-forward rule, ASR in Audit only, USB not blocked, Safe Links assigned to a subset. Keep an answer key.
2. **Recall check.** Every planted gap must appear as a finding with the right severity. A miss blocks release.
3. **Comparator check.** Compare CA results to CA Insight and CA Gap Analyzer on the same tenant, and explain every disagreement.
4. **Permission check.** Run the preflight as Global Reader and as the app registration, and record which modules degrade to Limited.
5. **Throughput.** Measure collection time on a large tenant and the What-If call count, tune caching and throttling, and record results.
6. **Interpretation time.** Track hours from run to delivered report on each real engagement. This is the metric that justifies any paid tool and the quarterly pricing.

## Build order

| Phase | Deliverable | Done when |
| --- | --- | --- |
| 1 | Preflight, run folder, manifest, snapshot collectors with hashes | Lab tenant snapshot reproduces and manifest lists Ready, Limited, Blocked correctly |
| 2 | Fact tables and joined privileged-user table | Table matches manual check of admins and MFA in the lab tenant |
| 3 | Rules layer, finding schema, mapping file, completeness audit | No unmapped Maester tests or CIS v7 items without a reason |
| 4 | Pinned Maester run with custom tests for endpoint matrix and Defender coverage by assignment | Planted endpoint and mail gaps all detected |
| 5 | CA scenario generator and What-If engine, heatmap | Agrees with CA Insight and CA Gap Analyzer on lab tenant |
| 6 | HTML takeaways report with coverage matrix and scope statement | A client-ready sample report from the lab tenant |
| 7 | HIBP module and optional Claude narrative skill with pseudonymization | Joined exposure table and structured-input-only narrative |
| 8 | Quarterly diff and trend, remediation catalog | Second run shows changed, new and resolved findings by ID |

## Open questions, coverage matrix and scope statement

**Open and unverified items**

- [ ] Which read endpoints work under Global Reader: `userRegistrationDetails`, Intune policy reads, advanced hunting. Test in the lab tenant.
- [ ] Graph What-If endpoint limits: it is beta, cannot evaluate some conditions, and has no documented rate limits.
- [ ] Tenable terms for recurring client scans, and whether the audit files justify the cost versus Maester.
- [ ] Licenses for PSGuerrilla, CaOutcome and idPowerApp before reusing any ideas or code.
- [ ] Maester 3.0 migration timing and the native test format.
- [ ] Reference tools for endpoint checks (`msec`, TenantPulse): fit and license.
- [ ] Pricing model for quarterly scans and the engagement letter wording for scope, consent and data handling.

**Coverage matrix (included in every report).** Attack-path weighting differs by source: Microsoft's 2025 Digital Defense Report puts over 97% of identity attacks as password spray or brute force, with token theft and MFA attacks under 3%, while M-Trends 2026 reports vishing as the second most common initial vector at 11% and prior compromise at 30%. The report states which of these paths the technical tenant checks reduce, and which they do not.

| Attacker path | Tenant controls assessed | Not covered by this assessment |
| --- | --- | --- |
| Password spray and brute force | CA, legacy auth, MFA registration, smart lockout settings | Password hygiene outside tenant settings |
| Token theft and AiTM phishing | Phishing-resistant strength in CA, token protection, device compliance | User behavior |
| Vishing and help desk reset | Self-service reset settings, authentication method policy, admin reset roles | Help desk process and caller verification |
| Malicious app consent | Consent settings, app permissions, owner-less apps | Business approval process |
| Mailbox persistence and exfiltration | Forwarding, inbox and transport rules, audit | User reporting |
| Endpoint script and USB execution | ASR, Device Control, App Control, AV and tamper settings | Unmanaged devices outside Intune and Defender |
| Prior compromise and leaked credentials | HIBP exposure joined to identities | Dark web sources outside HIBP |

**Scope statement for reports.** "This assessment evaluated technical configuration of the Microsoft 365 tenant (Entra ID, Intune, Defender, Exchange Online) as of \[run time\]. It did not evaluate interviews, process, user behavior, on-premises systems, or endpoints outside Intune and Defender settings. Items marked Not assessed could not be collected with the access provided."
