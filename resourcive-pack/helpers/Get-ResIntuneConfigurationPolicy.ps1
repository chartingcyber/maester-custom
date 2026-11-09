function Get-ResIntuneConfigurationPolicy {
    <#
    .SYNOPSIS
    Returns the Windows settings catalog policies of Intune with their flattened settings and who they are assigned to.

    .DESCRIPTION
    Reads deviceManagement/configurationPolicies for Windows 10 and later (this covers endpoint security profiles
    such as Account protection, Attack surface reduction, Antivirus, Disk encryption and App Control, which are
    settings catalog policies under the hood), then each policy's settings and assignments. Returns one object per
    policy: Id, Name, TemplateFamily, Settings (DefinitionId, Value, Depth) and Assignment (see
    ConvertTo-ResAssignmentSummary).

    Policies that the caller does not need can be left out with -DefinitionIdPattern, which keeps only policies that
    have at least one setting whose definition ID matches the pattern, and -TemplateFamily.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        # Keep only policies with a setting whose definition ID (lower case) matches this regular expression.
        [string] $DefinitionIdPattern,

        # Keep only policies of this template family, for example endpointSecurityAttackSurfaceReduction.
        [string] $TemplateFamily
    )

    $uri = "deviceManagement/configurationPolicies?`$filter=platforms has 'windows10'&`$select=id,name,description,platforms,templateReference,isAssigned"
    $policies = @(Invoke-MtGraphRequest -RelativeUri $uri -ApiVersion beta)

    foreach ($policy in $policies) {
        $family = [string]$policy.templateReference.templateFamily
        if ($TemplateFamily -and $family -ne $TemplateFamily) { continue }

        $settingRows = @(Invoke-MtGraphRequest -RelativeUri "deviceManagement/configurationPolicies('$($policy.id)')/settings?`$top=1000" -ApiVersion beta)
        $flat = @($settingRows | ForEach-Object { ConvertTo-ResFlatSetting -SettingInstance $_.settingInstance })

        if ($DefinitionIdPattern -and -not ($flat | Where-Object { $_.DefinitionId -match $DefinitionIdPattern })) { continue }

        $assignments = @()
        if ($policy.isAssigned -ne $false) {
            $assignments = @(Invoke-MtGraphRequest -RelativeUri "deviceManagement/configurationPolicies('$($policy.id)')/assignments" -ApiVersion beta)
        }

        [pscustomobject]@{
            Id             = [string]$policy.id
            Name           = [string]$policy.name
            TemplateFamily = $family
            Settings       = $flat
            Assignment     = ConvertTo-ResAssignmentSummary -Assignment $assignments
        }
    }
}
