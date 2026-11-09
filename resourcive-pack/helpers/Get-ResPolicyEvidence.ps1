function Get-ResPolicyEvidence {
    <#
    .SYNOPSIS
    Collects, from settings catalog policies, the evidence that a control is set, with the mode and the assignment.

    .DESCRIPTION
    For each policy that has a setting whose definition ID equals DefinitionId (or matches DefinitionIdPattern),
    resolves the setting's value to a mode and returns one evidence object: Policy, PolicyId, DefinitionId, Value,
    Mode and Assignment. The result is what Get-ResControlStatus takes.

    A value that matches EnforcedPattern is Enforced, a value that matches AuditPattern is Audit, and any other
    value produces no evidence.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        # The policies from Get-ResIntuneConfigurationPolicy.
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Policy,

        # The exact settings catalog definition ID, in lower case.
        [string] $DefinitionId,

        # A regular expression for the definition ID, for settings that come in several forms.
        [string] $DefinitionIdPattern,

        # A regular expression for the setting values that mean the control is enforced, for example '_block$'.
        [Parameter(Mandatory)]
        [string] $EnforcedPattern,

        # A regular expression for the setting values that mean the control only audits or warns, for example '_(audit|warn)$'.
        [string] $AuditPattern
    )

    foreach ($item in $Policy) {
        foreach ($setting in @($item.Settings)) {
            $isMatch = if ($DefinitionId) { $setting.DefinitionId -eq $DefinitionId } else { $setting.DefinitionId -match $DefinitionIdPattern }
            if (-not $isMatch) { continue }
            $value = [string]$setting.Value
            $mode = if ($value -match $EnforcedPattern) { 'Enforced' } elseif ($AuditPattern -and $value -match $AuditPattern) { 'Audit' } else { $null }
            if (-not $mode) { continue }
            [pscustomobject]@{
                Policy       = $item.Name
                PolicyId     = $item.Id
                DefinitionId = $setting.DefinitionId
                Value        = $setting.Value
                Mode         = $mode
                Assignment   = $item.Assignment
            }
        }
    }
}
