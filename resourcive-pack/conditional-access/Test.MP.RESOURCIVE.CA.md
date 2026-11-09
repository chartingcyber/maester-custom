Checks that Conditional Access gives the outcome you expect when a real user of the tenant signs in, by asking the Conditional Access What If API about one sign-in scenario per row.

Policies that look right can still leave a gap: an exclusion that covers a group of admins, a policy that only covers browsers, a legacy client that no policy blocks. Reading the policies does not show the combined result for a given user, so this test signs in as real users in What If and looks at what the policies together would do. An attacker who phishes or sprays a password uses the same gaps (valid cloud accounts, password spraying).

#### How the scenarios are chosen

- **Personas are real users.** Every user who holds a privileged directory role (active or, with Entra ID P2 or Governance, eligible) is a persona of their own, up to `Resourcive.CA.MaxPrivilegedUsers`. All other users are grouped by which policies include or exclude them, and one real user per group represents it, labelled `Member:class-N` or `Guest:class-N`. Users are never invented.
- **Conditions come from your policies.** Applications, named-location countries, trusted IP ranges and user actions are taken from what the policies reference. A policy that targets *All resources* or *Office 365* is probed with concrete first-party app IDs (Exchange Online, SharePoint Online, Teams, the Azure portal, Azure Resource Manager), because What If does not match app groups. Application IDs are shown with their display name (looked up once per ID with `servicePrincipals?$filter=appId eq '<id>'`; the ID is shown when a name cannot be found).
- **Platforms are always all four.** Windows, iOS, Android and macOS are always probed, plus any other platform a policy names (for example linux or windowsPhone). The list is never cut down to the platforms the policies name, and the base platform of every persona is windows.
- **The home location avoids your geoblocks.** The home country is the first named-location country that no block policy and no policy conditioned on that location (enforced or report-only) matches. When every named country collides, a neutral default (US, then CA, GB, DE, AU) is used. The notes say which home was chosen and why, and which countries were skipped and by which policy. A report-only block that is conditioned on a location does not by itself make a row "coverage depends on report-only".
- **Legacy clients are probed once per policy path.** Exchange Online is probed with both `exchangeActiveSync` and `other`, one representative other application (SharePoint Online) with `other`, and every application that a policy with a legacy client condition names explicitly. Not every application is probed with every legacy client.
- **One factor at a time.** Each persona gets a baseline (home location, windows, browser and mobile or desktop client, each app) and then one condition is varied at a time (legacy clients, platforms, locations, user actions, risk). Every scenario sets client app type, platform, country, sign-in risk and user risk explicitly, because What If does not evaluate a condition it is not given.
- **Round-robin cap.** At most `Resourcive.CA.MaxScenarios` (default 300) scenarios run. The cap is applied round-robin by persona: every persona first gets its legacy probe, a modern baseline, one platform variation and one location variation (the outside country), and only then does any persona get a second scenario of anything. Privileged personas are visited first, emergency accounts last; within a persona, legacy clients come before the rest and non-privileged users on admin portals, Azure and other apps come last. When the cap cuts scenarios, every row says so, including which axes that row's persona lost, and the notes list every persona that lost scenarios and which axes.
- **Emergency access accounts** (the `EmergencyAccessAccounts` setting) are recognised for every kind of persona, are never used to represent a class of users, and are tested on their own as informational. When no privileged user is found, the rows carry a note that no Critical expectation applied.

#### How the outcome is classified

Only enforced policies (state *On*) that apply decide the outcome. Every applying policy must be satisfied, so their requirements add up; within one policy that uses *Require one of the selected controls* the easiest alternative decides.

| Outcome | Meaning |
| --- | --- |
| Block | An enforced policy blocks the sign-in. |
| PhishingResistant | An authentication strength that allows only Windows Hello for Business, FIDO2 or multifactor certificates. |
| MFA | MFA or an MFA authentication strength is required. |
| DeviceRequired | A compliant or domain-joined device is required, but not MFA. |
| AppRequired | An approved client app or an app protection policy is required, but not MFA or a device. It is not the same as NoControl, and it does not meet an MFA expectation (the row is Investigate). |
| NoControl | No enforced policy applies, or none requires a control. |
| NotAssessed | What If could not evaluate a policy (`notEnoughInformation`, `invalidCondition`, `invalidPolicy`), or the What If call kept failing after retries. Shown as Investigate with the reason, never as a pass and never as an error. |

Policies in report-only mode are listed separately. If the expectation would be met only by a report-only policy, the row is Investigate: report-only policies are not enforced. A report-only block that is conditioned on a location (a geoblock you are trialling) is listed but does not count as such a dependency.

**Legacy clients and de facto blocks.** A legacy client (`exchangeActiveSync`, `other`) cannot satisfy MFA, a device requirement or an approved-app requirement. When Block is expected and the outcome is MFA, DeviceRequired or AppRequired, the sign-in is blocked in effect: the row passes with the note "de facto block, an explicit block policy is still recommended" and a finding severity of Low. NoControl on a legacy client stays a failure.

**Retries.** A What If call that returns HTTP 429, 500, 502, 503 or 504, or times out, is retried with a growing delay (up to four attempts). If it still fails, the row is Investigate with the reason, not an error. Permission and licence errors are not retried.

Each row also shows the persona's class size and which policies include or exclude the class.

#### Default expectations

| Scenario | Expected | Severity |
| --- | --- | --- |
| Legacy client (`exchangeActiveSync`, `other`), privileged user | Block | Critical |
| Legacy client, any other user | Block | High |
| Privileged user, any other scenario | MFA or stronger (phishing-resistant is reported) | Critical |
| Member or guest, Microsoft 365 app, modern client | MFA or stronger | High |
| High sign-in risk (Entra ID P2) | MFA or stronger | High |
| High user risk (Entra ID P2) | Block, password change or MFA | High |
| Anything else, and emergency access accounts | Informational: shown for review, never fails | Info |

Emergency access accounts are the ones in the `EmergencyAccessAccounts` setting; policies exclude them on purpose.

#### Licence behaviour

- The test needs Microsoft Entra ID P1 (included in Microsoft 365 Business Premium). Without it the row is Skipped with a reason that starts `Not licensed:`, whether Maester's licence gate or the test's own check noticed.
- Every row carries a note on the risk axes: `Risk axes probed (Entra ID P2 present)` or `Risk axes omitted: Entra ID P2 not licensed`, together with the service plan checked (`AAD_PREMIUM_P2` in the tenant's subscribed SKUs) and whether it was found. Without Entra ID P2 the risk scenarios are left out. Policies that need a risk level are evaluated with risk *None*. Eligible (PIM) assignments cannot be read without P2 or Governance, so users who hold only eligible roles are not tested as privileged users; the rows say so.
- A Graph licence error becomes `Not licensed:` and a permission error becomes `Not authorized:` with what to add. They are never a pass.

#### Settings (GlobalSettings in the Maester config)

| Setting | Default | Meaning |
| --- | --- | --- |
| `Resourcive.CA.MaxScenarios` | 300 | The most scenarios to run. |
| `Resourcive.CA.MaxPrivilegedUsers` | 25 | The most privileged users tested individually. |
| `Resourcive.CA.IncludeReportOnly` | true | Include report-only policies when grouping users and choosing conditions. |
| `Resourcive.CA.MaxUsers` | 5000 | The most enabled users read. |
| `Resourcive.CA.MaxExplicitApps` | 8 | The most application IDs taken from policies. |
| `Resourcive.CA.MaxLocations` | 4 | The most locations probed, including one outside every named location. |
| `Resourcive.CA.PersonaFile` | empty | A JSON file that keeps the personas between runs, so a run is reproducible. |
| `Resourcive.CA.RefreshPersonas` | false | Read the tenant again and rewrite the persona file. |
| `Resourcive.CA.DesiredStateFile` | empty | The desired-state file below. |
| `Resourcive.CA.RedactUserNames` | false | Show persona labels instead of user principal names. |

The test parameter `ThrottleMilliseconds` (default 250) is the wait before each What If call. The family is marked long running, so it runs with `-IncludeLongRunning` or when its ID is named.

#### Desired-state file

An optional JSON file overrides the defaults. Rules are tried in order and the first match wins. A rule can match `Persona` (`Privileged`, `Member`, `Guest` or `*`), `Client`, `App` (name, key or application ID), `Platform`, `Location` (`home`, `outside` or `cc-XX`), `Action` and `Axis` (`baseline`, `client`, `platform`, `location`, `action`, `risk`); each is a string, a list of strings or `*`.

```json
{
  "DeviceRequiredSatisfiesMfa": false,
  "Rules": [
    { "Persona": "Privileged", "App": "portals", "Expect": "PhishingResistant", "Severity": "Critical", "Note": "Admin portals need a passkey." },
    { "Persona": "Member", "App": ["arm", "portals"], "Expect": "Block", "Severity": "High" },
    { "Persona": "*", "Location": "outside", "Expect": "Block", "Severity": "High" },
    { "Persona": "Guest", "App": "*", "Expect": "Info" }
  ]
}
```

`Expect` is `Block`, `MFA`, `PhishingResistant`, `Remediate` or `Info`. `Severity` is `Critical`, `High`, `Medium`, `Low` or `Info`. `DeviceRequiredSatisfiesMfa` lets a device requirement meet an MFA expectation.

#### Remediation action

1. In the **Microsoft Entra admin center**, go to **Entra ID** > **Conditional Access** > **[Policies](https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies)** and open the policies named in the failing row's table, or find the gap in the **[What If](https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/WhatIf)** tool with the same user and conditions.
2. For a legacy client that is not blocked, create a policy that targets *Exchange ActiveSync clients* and *Other clients* for all users and blocks access. Start in report-only mode.
3. For a user with no MFA, add the user or their group to a policy that requires MFA or an authentication strength, or remove the exclusion that lets them through. Keep emergency access accounts excluded.
4. For a coverage that depends on report-only policies, review the policy's impact in report-only mode, then switch it to **On**.
5. Run the test again.

#### Related links

* [Conditional Access What If tool](https://learn.microsoft.com/entra/identity/conditional-access/what-if-tool)
* [conditionalAccessRoot: evaluate (Microsoft Graph)](https://learn.microsoft.com/graph/api/conditionalaccessroot-evaluate)
* [whatIfAnalysisResult resource type](https://learn.microsoft.com/graph/api/resources/whatifanalysisresult)
* [Conditional Access authentication strengths](https://learn.microsoft.com/entra/identity/authentication/concept-authentication-strengths)
* [Conditional Access license requirements](https://learn.microsoft.com/entra/identity/conditional-access/overview#license-requirements)

<!--- Results --->
%TestResult%
