No enabled mail flow (transport) rule redirects, copies or blind copies mail to a recipient outside the organization.

A transport rule that adds an external recipient works on all mail that matches it, for every user, and users never see it. Attackers who reach an Exchange administrator account use this to read mail for a whole department. Legitimate uses exist (an archive, a compliance copy), so each result is a question to answer: who created it, and is the recipient still ours?

The check reads the enabled transport rules and flags external addresses in the redirect, blind copy, copy and add-recipient actions. Recipients given by name rather than address cannot be classified and are listed for review. Rules that set the spam confidence level to bypass filtering are covered by MT.1043.

Licence: any Exchange Online mailbox licence.

#### Remediation action

1. In the [Exchange admin center](https://admin.exchange.microsoft.com/#/transportrules), open each rule in the result and confirm its owner and purpose using the audit log.
2. Disable or delete the rule if it is not needed, or change the action to an internal archive mailbox.
3. Limit who can create transport rules by reviewing members of the Organization Management and Transport Hygiene role groups.

#### Related links

* [Mail flow rules (transport rules) in Exchange Online](https://learn.microsoft.com/exchange/security-and-compliance/mail-flow-rules/mail-flow-rules)
* [Mail flow rule actions](https://learn.microsoft.com/exchange/security-and-compliance/mail-flow-rules/mail-flow-rule-actions)

<!--- Results --->
%TestResult%
