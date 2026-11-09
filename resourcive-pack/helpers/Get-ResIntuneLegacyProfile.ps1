function Get-ResIntuneLegacyProfile {
    <#
    .SYNOPSIS
    Returns the Windows device configuration profiles (templates, custom OMA-URI) and Administrative Templates profiles of Intune with their assignments.

    .DESCRIPTION
    Not every control is set in the settings catalog. This reads two older profile types:
    - deviceManagement/deviceConfigurations of type windows10* (the Device restrictions template, whose properties
      such as storageBlockRemovableStorage are plain booleans, and Custom profiles, whose omaSettings hold OMA-URI and value);
    - deviceManagement/groupPolicyConfigurations (Administrative Templates), with each enabled or disabled
      definition and its display name and category path.

    Returns one object per profile: Id, Name, Kind (DeviceRestrictions, Custom, AdministrativeTemplates, Other),
    Properties (the profile object), OmaSettings (OmaUri and Value), AdmxDefinitions (DisplayName, CategoryPath,
    Enabled) and Assignment (see ConvertTo-ResAssignmentSummary).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        # Skip the Administrative Templates profiles (they need one extra call per profile).
        [switch] $SkipAdministrativeTemplates
    )

    $profiles = @(Invoke-MtGraphRequest -RelativeUri 'deviceManagement/deviceConfigurations?$expand=assignments' -ApiVersion beta)
    foreach ($item in $profiles) {
        $type = [string]$item.'@odata.type'
        if ($type -notlike '#microsoft.graph.windows10*') { continue }
        $kind = switch -Wildcard ($type) {
            '*windows10GeneralConfiguration' { 'DeviceRestrictions' }
            '*windows10CustomConfiguration' { 'Custom' }
            default { 'Other' }
        }
        [pscustomobject]@{
            Id              = [string]$item.id
            Name            = [string]$item.displayName
            Kind            = $kind
            Properties      = $item
            OmaSettings     = @(@($item.omaSettings) | Where-Object { $_ } | ForEach-Object { [pscustomobject]@{ OmaUri = [string]$_.omaUri; Value = [string]$_.value } })
            AdmxDefinitions = @()
            Assignment      = ConvertTo-ResAssignmentSummary -Assignment @($item.assignments)
        }
    }

    if ($SkipAdministrativeTemplates) { return }

    $admxProfiles = @(Invoke-MtGraphRequest -RelativeUri 'deviceManagement/groupPolicyConfigurations?$expand=assignments' -ApiVersion beta)
    foreach ($item in $admxProfiles) {
        $values = @(Invoke-MtGraphRequest -RelativeUri "deviceManagement/groupPolicyConfigurations/$($item.id)/definitionValues?`$expand=definition" -ApiVersion beta)
        [pscustomobject]@{
            Id              = [string]$item.id
            Name            = [string]$item.displayName
            Kind            = 'AdministrativeTemplates'
            Properties      = $item
            OmaSettings     = @()
            AdmxDefinitions = @($values | ForEach-Object {
                    [pscustomobject]@{
                        DisplayName  = [string]$_.definition.displayName
                        CategoryPath = [string]$_.definition.categoryPath
                        ClassType    = [string]$_.definition.classType
                        Enabled      = [bool]$_.enabled
                    }
                })
            Assignment      = ConvertTo-ResAssignmentSummary -Assignment @($item.assignments)
        }
    }
}
