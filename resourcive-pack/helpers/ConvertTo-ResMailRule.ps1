function ConvertTo-ResMailRule {
    <#
    .SYNOPSIS
    Normalises an Exchange Online protection policy rule into one shape, whatever cmdlet returned it.

    .DESCRIPTION
    Get-EOPProtectionPolicyRule, Get-ATPProtectionPolicyRule, Get-ATPBuiltInProtectionRule, Get-SafeLinksRule,
    Get-SafeAttachmentRule and Get-AntiPhishRule all describe who a policy applies to with the same recipient
    conditions and exceptions. Returns Name, Kind (Strict, Standard, BuiltIn or Custom), Enabled, Priority, the three
    conditions (SentTo, SentToMemberOf, RecipientDomainIs) and the three exceptions, as lower-case string arrays.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        # A rule object from one of the cmdlets above.
        [Parameter(Mandatory, ValueFromPipeline)]
        $Rule,

        # Force the kind. When omitted the kind is read from the rule name.
        [ValidateSet('Strict', 'Standard', 'BuiltIn', 'Custom')]
        [string] $Kind
    )

    process {
        $name = [string]$(if ($Rule.Name) { $Rule.Name } else { $Rule.Identity })
        if (-not $Kind) {
            $Kind = if ($name -match 'Strict Preset Security Policy') { 'Strict' }
            elseif ($name -match 'Standard Preset Security Policy') { 'Standard' }
            elseif ($name -match 'Built-In Protection') { 'BuiltIn' }
            else { 'Custom' }
        }

        function ConvertTo-LowerList {
            param($Value)
            @(@($Value) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() })
        }

        # State is Enabled or Disabled on protection rules; some rule types expose a boolean Enabled instead.
        $enabled = if ($Rule.PSObject.Properties['State'] -and $Rule.State) { [string]$Rule.State -eq 'Enabled' }
        elseif ($Rule.PSObject.Properties['Enabled']) { [bool]$Rule.Enabled }
        else { $true }

        [pscustomobject]@{
            Name                      = $name
            Kind                      = $Kind
            Enabled                   = $enabled
            Priority                  = $Rule.Priority
            SentTo                    = ConvertTo-LowerList -Value $Rule.SentTo
            SentToMemberOf            = ConvertTo-LowerList -Value $Rule.SentToMemberOf
            RecipientDomainIs         = ConvertTo-LowerList -Value $Rule.RecipientDomainIs
            ExceptIfSentTo            = ConvertTo-LowerList -Value $Rule.ExceptIfSentTo
            ExceptIfSentToMemberOf    = ConvertTo-LowerList -Value $Rule.ExceptIfSentToMemberOf
            ExceptIfRecipientDomainIs = ConvertTo-LowerList -Value $Rule.ExceptIfRecipientDomainIs
        }
    }
}
