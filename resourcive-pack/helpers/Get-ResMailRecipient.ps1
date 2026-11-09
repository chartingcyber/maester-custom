function Get-ResMailRecipient {
    <#
    .SYNOPSIS
    Returns the enabled user mailboxes of the tenant in the shape that Test-ResMailRuleApplies needs.

    .DESCRIPTION
    Reads the user mailboxes from Exchange Online (Get-MtExo -Request EXOMailbox) and the account state from Microsoft
    Graph. Returns one object per enabled user mailbox: DisplayName, UserPrincipalName, PrimarySmtpAddress, Domain and
    Addresses (lower-case user principal name and primary address). Shared, room and equipment mailboxes and disabled
    accounts are left out, because they are not people who read mail and click links.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $mailboxes = @(Get-MtExo -Request EXOMailbox | Where-Object { $_.RecipientTypeDetails -eq 'UserMailbox' })
    $users = @(Invoke-MtGraphRequest -RelativeUri 'users' -ApiVersion v1.0 -Select id, userPrincipalName, accountEnabled, mail)
    $enabled = @{}
    foreach ($user in $users) {
        if ($user.userPrincipalName) { $enabled[([string]$user.userPrincipalName).ToLowerInvariant()] = [bool]$user.accountEnabled }
    }

    foreach ($mailbox in $mailboxes) {
        $upn = ([string]$mailbox.UserPrincipalName).ToLowerInvariant()
        if ($enabled.ContainsKey($upn) -and -not $enabled[$upn]) { continue }
        $primary = ([string]$mailbox.PrimarySmtpAddress).ToLowerInvariant()
        [pscustomobject]@{
            DisplayName        = [string]$mailbox.DisplayName
            UserPrincipalName  = $upn
            PrimarySmtpAddress = $primary
            Domain             = if ($primary -match '@(.+)$') { $Matches[1] } else { '' }
            Addresses          = @(@($upn, $primary) | Where-Object { $_ } | Select-Object -Unique)
        }
    }
}
