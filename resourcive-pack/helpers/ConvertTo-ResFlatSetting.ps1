function ConvertTo-ResFlatSetting {
    <#
    .SYNOPSIS
    Flattens the nested settingInstance of an Intune settings catalog setting into a list of definition ID and value pairs.

    .DESCRIPTION
    A settings catalog setting is a tree: a choice setting holds child settings, a group collection holds groups of
    children. This walks the whole tree and returns one object per node that carries a value, with the definition ID
    in lower case, the value as text (the choice value such as ..._block, or the simple value) and the depth.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        # A settingInstance object from deviceManagement/configurationPolicies/{id}/settings.
        [Parameter(Mandatory, ValueFromPipeline)]
        [AllowNull()]
        $SettingInstance,

        # The depth of this node. Used by the recursion.
        [int] $Depth = 0
    )

    process {
        if ($null -eq $SettingInstance) { return }

        $definitionId = ([string]$SettingInstance.settingDefinitionId).ToLowerInvariant()
        $value = $null
        $children = @()

        if ($SettingInstance.choiceSettingValue) {
            $value = [string]$SettingInstance.choiceSettingValue.value
            $children = @($SettingInstance.choiceSettingValue.children)
        } elseif ($SettingInstance.simpleSettingValue) {
            $value = [string]$SettingInstance.simpleSettingValue.value
        } elseif ($SettingInstance.simpleSettingCollectionValue) {
            $value = (@($SettingInstance.simpleSettingCollectionValue) | ForEach-Object { [string]$_.value }) -join ';'
        } elseif ($SettingInstance.choiceSettingCollectionValue) {
            $value = (@($SettingInstance.choiceSettingCollectionValue) | ForEach-Object { [string]$_.value }) -join ';'
            $children = @($SettingInstance.choiceSettingCollectionValue | ForEach-Object { $_.children })
        } elseif ($SettingInstance.groupSettingCollectionValue) {
            $children = @($SettingInstance.groupSettingCollectionValue | ForEach-Object { $_.children })
        } elseif ($SettingInstance.groupSettingValue) {
            $children = @($SettingInstance.groupSettingValue.children)
        }

        if ($definitionId) {
            [pscustomobject]@{
                DefinitionId = $definitionId
                Value        = $value
                Depth        = $Depth
            }
        }

        foreach ($child in $children) {
            if ($null -ne $child) { ConvertTo-ResFlatSetting -SettingInstance $child -Depth ($Depth + 1) }
        }
    }
}
