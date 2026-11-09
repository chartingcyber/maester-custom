function Select-ResCaScenario {
    <#
    .SYNOPSIS
    Applies the scenario cap round-robin by persona, so that no persona is starved.

    .DESCRIPTION
    Takes scenarios from New-ResCaScenario and returns at most MaxScenarios of them. Each persona's scenarios are
    ordered by Round (1 is the core set: legacy probe, modern baseline, one platform variation and one location
    variation), then Priority, then Key. The cap is then applied one scenario per persona at a time, so every
    persona gets its core set before any persona gets a second of anything else. Personas are visited privileged
    first, then members and guests, then emergency access accounts, so a cap too small for every persona's core
    set cuts the least important personas.

    The returned objects carry Truncated (the number of scenarios left out), so the caller can say so in the
    result. Use Get-ResCaTruncationNote to list which personas lost which axes.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        # Scenarios from New-ResCaScenario.
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Scenario,

        # The most scenarios to keep.
        [ValidateRange(1, 100000)]
        [int] $MaxScenarios = 300
    )

    $all = @($Scenario | Where-Object { $_ })
    function Get-PersonaOrder {
        param($Persona)
        if ($Persona.IsEmergencyAccess) { return 3 }
        switch ([string]$Persona.Kind) { 'Privileged' { 0 } 'Member' { 1 } default { 2 } }
    }
    $personaKeys = @($all | Group-Object PersonaKey | Sort-Object @{ Expression = { Get-PersonaOrder $_.Group[0].Persona } }, @{ Expression = { $_.Name } })
    $lists = @(foreach ($g in $personaKeys) {
            , @($g.Group | Sort-Object Round, Priority, Key)
        })

    $kept = [System.Collections.Generic.List[object]]::new()
    $depth = 0
    $more = $true
    while ($more -and $kept.Count -lt $MaxScenarios) {
        $more = $false
        foreach ($list in $lists) {
            if ($depth -lt $list.Count) {
                $more = $true
                if ($kept.Count -lt $MaxScenarios) { $kept.Add($list[$depth]) }
            }
        }
        $depth++
    }
    $left = $all.Count - $kept.Count
    foreach ($s in $kept) { $s | Add-Member -NotePropertyName Truncated -NotePropertyValue $left -Force }
    $kept.ToArray()
}
