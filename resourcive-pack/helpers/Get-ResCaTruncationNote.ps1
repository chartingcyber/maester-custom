function Get-ResCaTruncationNote {
    <#
    .SYNOPSIS
    Says which personas lost which axes to the scenario cap.

    .DESCRIPTION
    Compares all scenarios with the ones kept and returns one object per persona that lost scenarios, with
    PersonaKey, Label, Lost (the number) and Text (for example "priv-01 Privileged:GlobalAdministrator lost 3
    scenarios: legacy clients x1, platforms x2"). Returns nothing when the cap cut nothing.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        # Every scenario from New-ResCaScenario.
        [AllowEmptyCollection()]
        [object[]] $All = @(),

        # The scenarios kept by Select-ResCaScenario.
        [AllowEmptyCollection()]
        [object[]] $Kept = @()
    )

    $names = @{ baseline = 'baseline applications'; client = 'legacy clients'; platform = 'platforms'; location = 'locations'; action = 'user actions'; risk = 'risk levels' }
    $keptKeys = @{}
    foreach ($s in @($Kept | Where-Object { $_ })) { $keptKeys[$s.Key] = $true }
    $lost = @($All | Where-Object { $_ -and -not $keptKeys.ContainsKey($_.Key) })
    foreach ($g in ($lost | Group-Object PersonaKey | Sort-Object Name)) {
        $axes = @($g.Group | Group-Object Axis | Sort-Object Name | ForEach-Object {
                $label = if ($names.ContainsKey($_.Name)) { $names[$_.Name] } else { $_.Name }
                '{0} x{1}' -f $label, $_.Count
            })
        $persona = $g.Group[0].Persona
        [pscustomobject]@{
            PersonaKey = [string]$g.Name
            Label      = [string]$persona.Label
            Lost       = $g.Count
            Text       = '{0} {1} lost {2} scenarios to the cap: {3}' -f $g.Name, $persona.Label, $g.Count, ($axes -join ', ')
        }
    }
}
