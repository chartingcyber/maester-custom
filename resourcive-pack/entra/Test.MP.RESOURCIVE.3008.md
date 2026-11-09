No third-party application, and no application without an owner, holds broad Microsoft Graph application permissions.

An application permission works without a signed-in user and cannot be stopped by the user's MFA. If an application owned by another organization (a multi-tenant app that someone consented to) can read all mail, write to the directory or change Conditional Access, that organization's breach is yours. If an application in your own tenant has such a permission and no owner, nobody is responsible for its secret or for removing it. This check reads the non-Microsoft service principals and the Graph application permissions granted to them, and lists those that hold one of the `RiskyPermissions` (permissions that can change or take over data, such as `Mail.ReadWrite`, `Mail.Send` or `Directory.ReadWrite.All`) and are either externally owned or ownerless. Applications that hold only `BroadReadPermissions` (such as `Mail.Read` or `User.Read.All`) are listed for review and make the result Investigate, because many legitimate products need them. When an owner or an application's permissions cannot be read, the result says so and does not call the application ownerless.

MT.1050 and MT.1051 look for paths to Global Administrator, and MT.1057 and MT.1199 look at credentials. This check covers the breadth of the permission and the ownership.

The check is long-running (one call per service principal). Reading needs `Application.Read.All` and `Directory.Read.All`.

#### Remediation action

1. For each application in the result, open it in [Enterprise applications](https://entra.microsoft.com/#view/Microsoft_AAD_IAM/StartboardApplicationsMenuBlade/~/AppAppsPreview) and check **Permissions**.
2. If the app is not needed, delete it. If it is needed, remove permissions it does not use, and assign an owner.
3. Turn on the [admin consent workflow](https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ConsentPoliciesMenuBlade/~/AdminConsentSettings) so new broad permissions need approval.

#### Related links

* [Review permissions granted to applications](https://learn.microsoft.com/entra/identity/enterprise-apps/manage-application-permissions)
* [Microsoft Graph permissions reference](https://learn.microsoft.com/graph/permissions-reference)

<!--- Results --->
%TestResult%
