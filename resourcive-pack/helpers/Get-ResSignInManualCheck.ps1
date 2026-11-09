function Get-ResSignInManualCheck {
    <#
    .SYNOPSIS
    Returns the markdown that tells a person how to do a sign-in check by hand, and why the check could not run.

    .DESCRIPTION
    The sign-in checks run on the Defender advanced hunting table EntraIdSignInEvents, which needs Microsoft Entra ID
    P2. When it cannot be used the check is Investigate, never a pass and never a silent skip, and this text says why
    and how to do the same check in the Microsoft Entra admin center.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Country', 'Legacy')]
        [string] $Kind,

        # Why the automatic check could not run, in words.
        [Parameter(Mandatory)]
        [string] $Reason,

        # Country, the expected countries, as text.
        [string] $ExpectedText = 'US, CA',

        [ValidateRange(1, 30)]
        [int] $LookbackDays = 7
    )

    $what = if ($Kind -eq 'Country') { "successful sign-ins from outside $ExpectedText" } else { 'successful sign-ins that used a legacy authentication protocol (IMAP, POP, SMTP AUTH, Exchange ActiveSync with basic authentication, other clients)' }
    $step = if ($Kind -eq 'Country') {
        "3. Add the **Location** filter if your portal offers it, or add the **Location** column (**Columns**) and sort by it. Look for any country other than $ExpectedText."
    } else {
        "3. Add the filter **Client app** and tick everything except *Browser* and *Mobile Apps and Desktop clients*: Exchange ActiveSync, IMAP4, POP3, SMTP, Authenticated SMTP, Exchange Web Services, Autodiscover, MAPI Over HTTP, Outlook Anywhere (RPC over HTTP), Other clients and similar. Any row is a legacy sign-in."
    }

    @"
**Not assessed automatically: $Reason**

**Why this is a manual check.** The only fast way to search sign-ins through Microsoft Graph is the Defender advanced hunting table ``EntraIdSignInEvents``, which holds interactive and non-interactive sign-ins and needs Microsoft Entra ID P2 and access to Defender advanced hunting. Without it, the Graph sign-in log takes about 40 seconds for each day, a filtered search over the whole period timed out in testing, and the v1.0 log omits non-interactive sign-ins, where legacy protocols mostly appear. This check would rather ask a person than report a result it cannot stand behind.

**How to check by hand** (looking for $what in the last $LookbackDays days):

1. Open the Microsoft Entra admin center (https://entra.microsoft.com) > **Entra ID** > **Monitoring & health** > **Sign-in logs**.
2. Set **Date** to the last $LookbackDays days and add the filter **Status: Success**.
$step
4. Do steps 2 and 3 on **both** tabs, *User sign-ins (interactive)* and *User sign-ins (non-interactive)*.
5. Any row that matches is a finding. **Download** exports the filtered rows as CSV to keep as evidence. If there are none on either tab, the check is clean for that period (the portal keeps 7 days with Entra ID Free and 30 days with P1 or P2).

If the tenant sends sign-in logs to Log Analytics, the *Sign-ins using legacy authentication* workbook (**Monitoring & health** > **Workbooks**) shows legacy sign-ins in seconds.
"@
}
