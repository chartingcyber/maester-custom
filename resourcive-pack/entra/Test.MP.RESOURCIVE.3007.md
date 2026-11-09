The Microsoft Secure Score recommendations with the most points still to gain, listed so that a person can review them.

Secure Score is Microsoft's own measure of how many of its recommended controls are in place. It is not a verdict, and the points do not equal risk, but its list of recommendations is a way to find controls that the other checks do not cover. This check reads the latest score and the control profiles and lists the controls that are not fully implemented, with the user impact and implementation cost that Microsoft assigns. It never fails; when there are gaps to review the result is **Investigate**.

Reading Secure Score through Graph needs the `SecurityEvents.Read.All` permission. The Defender portal's Secure Score page is not available to the Global Reader role (a documented limitation of that role), but the Graph API is. Confirm the role you run with.

#### Remediation action

1. Open [Microsoft Secure Score](https://security.microsoft.com/securescore) and review the recommended actions listed in the result.
2. For each, decide whether to implement, accept the risk, or mark as covered by a third-party tool, and record the decision.

#### Related links

* [Microsoft Secure Score](https://learn.microsoft.com/defender-xdr/microsoft-secure-score)
* [secureScoreControlProfile resource type](https://learn.microsoft.com/graph/api/resources/securescorecontrolprofile)

<!--- Results --->
%TestResult%
