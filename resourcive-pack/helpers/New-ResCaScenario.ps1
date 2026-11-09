function New-ResCaScenario {
    <#
    .SYNOPSIS
    Builds the What If scenarios for the personas, one factor at a time from a baseline.

    .DESCRIPTION
    A full cross product of personas, applications, client types, platforms, locations and risk levels is far too
    large, so each persona gets a baseline (home location, windows, browser, each application) and then one
    axis is varied at a time: legacy client types, platforms, locations, user actions and risk. The base platform
    is always windows (the first platform only when windows is not on the axis). Every scenario sets the client
    app type, device platform, country, sign-in risk and user risk explicitly, because What If does not
    evaluate a condition it is not given. Risk is None unless the scenario varies it.

    Legacy client types are probed once per distinct policy path, from the axis LegacyProbes: Exchange Online with
    exchangeActiveSync and other, one representative other application with other, and the applications that
    legacy-client policies name explicitly.

    Each scenario has a Priority (lower runs first) and a Round. Round 1 is the persona's core set: the legacy
    probe (Exchange Online, exchangeActiveSync), a modern baseline (Exchange Online, browser), one platform
    variation and one location variation (the outside location). Round 2 is everything else. Select-ResCaScenario
    applies the cap round-robin by persona over these rounds. Priority: legacy client types come before everything
    else, privileged personas before others, and probes of non-privileged users against admin portals, Azure and
    other apps come last. Emergency access accounts are informational.
    Returns scenario objects with Key, PersonaKey, Persona, App, UserAction, ClientAppType, DevicePlatform, Country,
    IpAddress, LocationKey, SignInRiskLevel, UserRiskLevel, Axis, Round and Priority.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        # Personas from Select-ResCaPersona.
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Persona,

        # Axes from Get-ResCaAxis.
        [Parameter(Mandatory)]
        $Axis
    )

    $homeLocation = $Axis.Locations | Where-Object { $_.Key -eq 'home' } | Select-Object -First 1
    $basePlatform = if (@($Axis.Platforms) -contains 'windows') { 'windows' } else { @($Axis.Platforms)[0] }
    $primary = @($Axis.Apps | Where-Object { $_.Key -eq 'exo' } | Select-Object -First 1)[0]
    if (-not $primary) { $primary = @($Axis.Apps)[0] }
    $legacyClients = @('exchangeActiveSync', 'other')
    $probes = @($Axis.LegacyProbes | Where-Object { $_ })
    if ($probes.Count -eq 0) { $probes = @([pscustomobject]@{ AppKey = $primary.Key; ClientTypes = $legacyClients }) }
    $otherPlatforms = @($Axis.Platforms | Where-Object { $_ -ne $basePlatform })
    $tier1Platform = $otherPlatforms | Select-Object -First 1
    $outsideLocation = $Axis.Locations | Where-Object { $_.Key -eq 'outside' } | Select-Object -First 1
    if (-not $outsideLocation) { $outsideLocation = $Axis.Locations | Where-Object { $_.Key -ne 'home' } | Select-Object -First 1 }

    function New-Scenario {
        param($persona, $app, $action, $client, $platform, $location, $signIn, $userRisk, $axisName, $round = 2)
        $appKey = if ($action) { "act-$action" } else { $app.Key }
        $parts = @($persona.Key, $appKey, $client, $platform, $location.Key, "sr$signIn", "ur$userRisk")
        $informational = ($persona.Kind -ne 'Privileged') -and ($action -or ($app.Group -ne 'M365'))
        $priority = if ($axisName -eq 'client') { if ($persona.Kind -eq 'Privileged') { 0 } else { 1 } }
        elseif ($informational) { 9 }
        elseif ($persona.Kind -eq 'Privileged' -and $axisName -eq 'baseline') { 2 }
        elseif ($axisName -eq 'baseline') { 3 }
        elseif ($axisName -eq 'platform') { 4 }
        elseif ($axisName -eq 'location') { 5 }
        elseif ($axisName -eq 'action') { 6 }
        else { 7 }
        [pscustomobject]@{
            Key             = ($parts -join '-').ToLowerInvariant()
            PersonaKey      = $persona.Key
            Persona         = $persona
            App             = $app
            UserAction      = $action
            ClientAppType   = $client
            DevicePlatform  = $platform
            Country         = $location.Country
            IpAddress       = $location.IpAddress
            LocationKey     = $location.Key
            SignInRiskLevel = $signIn
            UserRiskLevel   = $userRisk
            Axis            = $axisName
            Round           = $round
            Priority        = $priority
        }
    }

    $scenarios = [System.Collections.Generic.List[object]]::new()
    foreach ($p in $Persona) {
        # Modern baseline: every application in a browser and in a mobile or desktop client.
        foreach ($app in $Axis.Apps) {
            $round = if ($app.Key -eq $primary.Key) { 1 } else { 2 }
            $scenarios.Add((New-Scenario $p $app $null 'browser' $basePlatform $homeLocation 'None' 'None' 'baseline' $round))
            $scenarios.Add((New-Scenario $p $app $null 'mobileAppsAndDesktopClients' $basePlatform $homeLocation 'None' 'None' 'baseline'))
        }
        # Legacy clients: once per distinct policy path.
        foreach ($probe in $probes) {
            $app = @($Axis.Apps | Where-Object { $_.Key -eq $probe.AppKey } | Select-Object -First 1)[0]
            if (-not $app) { continue }
            foreach ($client in @($probe.ClientTypes)) {
                $round = if ($app.Key -eq $primary.Key -and $client -eq 'exchangeActiveSync') { 1 } else { 2 }
                $scenarios.Add((New-Scenario $p $app $null $client $basePlatform $homeLocation 'None' 'None' 'client' $round))
            }
        }
        foreach ($platform in $otherPlatforms) {
            $round = if ($platform -eq $tier1Platform) { 1 } else { 2 }
            $scenarios.Add((New-Scenario $p $primary $null 'browser' $platform $homeLocation 'None' 'None' 'platform' $round))
        }
        foreach ($location in ($Axis.Locations | Where-Object { $_.Key -ne 'home' })) {
            $round = if ($location.Key -eq $outsideLocation.Key) { 1 } else { 2 }
            $scenarios.Add((New-Scenario $p $primary $null 'browser' $basePlatform $location 'None' 'None' 'location' $round))
        }
        foreach ($action in $Axis.UserActions) {
            $scenarios.Add((New-Scenario $p $null $action 'browser' $basePlatform $homeLocation 'None' 'None' 'action'))
        }
        foreach ($level in $Axis.SignInRiskLevels) {
            $scenarios.Add((New-Scenario $p $primary $null 'browser' $basePlatform $homeLocation $level 'None' 'risk'))
        }
        foreach ($level in $Axis.UserRiskLevels) {
            $scenarios.Add((New-Scenario $p $primary $null 'browser' $basePlatform $homeLocation 'None' $level 'risk'))
        }
    }

    # Keys must be unique: a repeated persona/app/client/platform/location combination is one scenario.
    $seen = @{}
    foreach ($s in ($scenarios | Sort-Object Priority, PersonaKey, Key)) {
        if (-not $seen.ContainsKey($s.Key)) { $seen[$s.Key] = $true; $s }
    }
}
