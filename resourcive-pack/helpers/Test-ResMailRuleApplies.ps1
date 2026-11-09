function Test-ResMailRuleApplies {
    <#
    .SYNOPSIS
    Tells whether an Exchange Online protection policy rule applies to a recipient.

    .DESCRIPTION
    Implements the documented logic of recipient conditions and exceptions in Defender for Office 365 policies:
    - the rule must be enabled;
    - values of one condition use OR, different condition types use AND, and a rule with no condition applies to everyone;
    - an exception of any type that matches removes the recipient.
    The Built-in protection rule has exceptions only, so it applies to everyone not excepted.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        # A rule from ConvertTo-ResMailRule.
        [Parameter(Mandatory)]
        $Rule,

        # The recipient: Addresses (lower-case user principal name, mail and primary SMTP address) and Domain (primary SMTP domain).
        [Parameter(Mandatory)]
        $Recipient,

        # The hashtable that Resolve-ResGroupMemberAddress uses to avoid reading a group twice.
        [Parameter(Mandatory)]
        [hashtable] $Cache
    )

    if (-not $Rule.Enabled) { return $false }

    function Test-InGroup {
        param($Groups)
        foreach ($group in @($Groups)) {
            $members = Resolve-ResGroupMemberAddress -Identity $group -Cache $Cache
            foreach ($address in @($Recipient.Addresses)) { if ($members -contains $address) { return $true } }
        }
        return $false
    }
    function Test-IsUser {
        param($Users)
        foreach ($address in @($Recipient.Addresses)) { if (@($Users) -contains $address) { return $true } }
        return $false
    }
    function Test-InDomain {
        param($Domains)
        return (@($Domains) -contains ([string]$Recipient.Domain).ToLowerInvariant())
    }

    # Exceptions first: any match excludes the recipient.
    if (@($Rule.ExceptIfSentTo).Count -gt 0 -and (Test-IsUser -Users $Rule.ExceptIfSentTo)) { return $false }
    if (@($Rule.ExceptIfRecipientDomainIs).Count -gt 0 -and (Test-InDomain -Domains $Rule.ExceptIfRecipientDomainIs)) { return $false }
    if (@($Rule.ExceptIfSentToMemberOf).Count -gt 0 -and (Test-InGroup -Groups $Rule.ExceptIfSentToMemberOf)) { return $false }

    # Conditions: AND across types, OR within a type. No condition at all means everyone.
    if (@($Rule.SentTo).Count -gt 0 -and -not (Test-IsUser -Users $Rule.SentTo)) { return $false }
    if (@($Rule.RecipientDomainIs).Count -gt 0 -and -not (Test-InDomain -Domains $Rule.RecipientDomainIs)) { return $false }
    if (@($Rule.SentToMemberOf).Count -gt 0 -and -not (Test-InGroup -Groups $Rule.SentToMemberOf)) { return $false }
    return $true
}
