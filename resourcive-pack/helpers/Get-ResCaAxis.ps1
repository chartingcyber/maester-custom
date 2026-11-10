function Get-ResCaAxis {
    <#
    .SYNOPSIS
    Derives the values each What If condition takes from what the tenant's policies actually reference.

    .DESCRIPTION
    Applications: the explicit application IDs of the policies (up to a maximum) plus the well-known first-party
    applications, because a policy that targets All or Office 365 can only be probed with a concrete app ID.
    Client app types: always browser, mobileAppsAndDesktopClients, exchangeActiveSync and other, so legacy
    authentication is always probed. LegacyProbes says which application each legacy client type is probed
    against: Exchange Online with both legacy client types, one representative other application (SharePoint
    Online) with 'other', and every application that a policy with a legacy client condition names explicitly.
    Platforms: always windows, iOS, Android and macOS, plus any other platform a policy names (linux,
    windowsPhone); the list is never restricted to what policies name.
    Locations: a home location, further named-location countries, and one country that no named location
    contains. The home country is the first named-location country that no block policy and no policy conditioned
    on that location (enforced or report-only) matches, else a neutral default (US, then CA, GB, DE, AU), so a
    geoblock does not hit every home row. When the tenant has a trusted IPv4 named location, the home rows carry
    its first address. User actions: those the policies name. Risk levels: sign-in and user risk High, only when
    the tenant has Entra ID P2; a note always says whether risk axes were probed and which service plan decided it.

    Returns Apps, ClientTypes, LegacyProbes, Platforms, Locations, UserActions, SignInRiskLevels, UserRiskLevels
    and Notes.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        # Conditional Access policies.
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Policy,

        # Named locations (identity/conditionalAccess/namedLocations).
        [AllowEmptyCollection()]
        [object[]] $NamedLocation = @(),

        # Whether the tenant has Entra ID P2. $null when unknown, which is treated as not licensed.
        [AllowNull()]
        [System.Nullable[bool]] $P2Licensed = $false,

        # The service plan that decides the P2 answer, as Test-ResLicense checks it. Only used in the note.
        [string] $P2ServicePlan = 'AAD_PREMIUM_P2',

        # The most explicit application IDs to add to the well-known ones.
        [ValidateRange(0, 50)]
        [int] $MaxExplicitApps = 8,

        # The most locations to probe, including the outside location.
        [ValidateRange(1, 20)]
        [int] $MaxLocations = 4
    )

    $notes = [System.Collections.Generic.List[string]]::new()
    $guid = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    $live = @($Policy | Where-Object { $_.state -ne 'disabled' })

    # Applications
    $apps = [System.Collections.Generic.List[object]]::new()
    foreach ($app in (Get-ResCaWellKnownApp)) { $apps.Add($app) }
    $known = @($apps | ForEach-Object { $_.Id })
    $explicit = @($live | ForEach-Object { @($_.conditions.applications.includeApplications) + @($_.conditions.applications.excludeApplications) } |
            Where-Object { $_ -match $guid -and $known -notcontains $_ } | Select-Object -Unique)
    foreach ($id in ($explicit | Select-Object -First $MaxExplicitApps)) {
        $apps.Add([pscustomobject]@{ Key = $id.Substring(0, 8); Name = "Application $id"; Id = $id; Group = 'Other' })
    }
    if ($explicit.Count -gt $MaxExplicitApps) { $notes.Add("$($explicit.Count - $MaxExplicitApps) explicit application IDs from policies were not probed (MaxExplicitApps = $MaxExplicitApps).") }

    # Platforms: the four common ones are always probed, then any other platform a policy names.
    $platformMap = @{ android = 'Android'; ios = 'iOS'; windows = 'windows'; windowsphone = 'windowsPhone'; macos = 'macOS'; linux = 'linux' }
    $core = @('windows', 'iOS', 'Android', 'macOS')
    $named = @($live | ForEach-Object { @($_.conditions.platforms.includePlatforms) + @($_.conditions.platforms.excludePlatforms) } |
            Where-Object { $_ -and $platformMap.ContainsKey(([string]$_).ToLowerInvariant()) } |
            ForEach-Object { $platformMap[([string]$_).ToLowerInvariant()] } | Select-Object -Unique)
    $extra = @($named | Where-Object { $_ -and $core -notcontains $_ })
    $platforms = @($core) + $extra
    $notes.Add("Platforms probed: windows, iOS, Android and macOS always$(if ($extra.Count -gt 0) { ", plus $($extra -join ', ') named by policies" } else { '; no policy names another platform' }). The list is not restricted to the platforms policies name, because a policy that names one platform leaves the others to the policies that do not.")
    # Locations
    $countries = @($NamedLocation | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.countryNamedLocation' } |
            ForEach-Object { @($_.countriesAndRegions) } | Where-Object { $_ } | Select-Object -Unique)
    $trustedIp = $null
    foreach ($location in @($NamedLocation | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.ipNamedLocation' -and $_.isTrusted })) {
        foreach ($range in @($location.ipRanges)) {
            $candidate = Get-ResCaIpFromCidr -Cidr ([string]$range.cidrAddress)
            if ($candidate) { $trustedIp = $candidate; break }
        }
        if ($trustedIp) { break }
    }
    $usesIpLocations = @($NamedLocation | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.ipNamedLocation' }).Count -gt 0
    # Home country: avoid every country that a block policy or a location-conditioned policy matches.
    $countryLocations = @($NamedLocation | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.countryNamedLocation' })
    $collisions = @{}
    $candidates = @($countries) + @('US', 'CA', 'GB', 'DE', 'AU') | Select-Object -Unique
    foreach ($code in $candidates) {
        $ids = @($countryLocations | Where-Object { $_.id -and @($_.countriesAndRegions) -contains $code } | ForEach-Object { [string]$_.id })
        $hits = [System.Collections.Generic.List[string]]::new()
        foreach ($p in $live) {
            $include = @($p.conditions.locations.includeLocations | Where-Object { $_ } | ForEach-Object { [string]$_ })
            $exclude = @($p.conditions.locations.excludeLocations | Where-Object { $_ } | ForEach-Object { [string]$_ })
            $isBlock = @($p.grantControls.builtInControls) -contains 'block'
            $direct = @($include | Where-Object { $ids -contains $_ }).Count -gt 0
            $allowList = $isBlock -and ($include -contains 'All') -and $exclude.Count -gt 0 -and @($exclude | Where-Object { $ids -contains $_ }).Count -eq 0
            if ($direct -or $allowList) {
                $kind = if ($isBlock) { 'block' } else { 'conditioned on the location' }
                $mode = if ($p.state -eq 'enabledForReportingButNotEnforced') { 'report-only' } else { 'enforced' }
                $hits.Add("$($p.displayName) ($kind, $mode)")
            }
        }
        if ($hits.Count -gt 0) { $collisions[$code] = $hits.ToArray() }
    }
    $homeCountry = $null
    $homeWhy = ''
    foreach ($code in $countries) {
        if (-not $collisions.ContainsKey($code)) { $homeCountry = [string]$code; $homeWhy = 'a named-location country that no block or location-conditioned policy matches'; break }
    }
    if (-not $homeCountry) {
        foreach ($code in @('US', 'CA', 'GB', 'DE', 'AU')) {
            if (-not $collisions.ContainsKey($code)) {
                $homeCountry = $code
                $homeWhy = if ($countries.Count -gt 0) { 'a neutral default, because every named-location country is matched by a block or location-conditioned policy' } else { 'a neutral default, because the tenant has no country named location' }
                break
            }
        }
    }
    if (-not $homeCountry) { $homeCountry = 'US'; $homeWhy = 'the neutral default US, although a policy matches it too (every candidate collided)' }
    # Summarise the skipped countries. Listing each one with its policies made this note tens of kilobytes, and it is
    # copied into every scenario result, which made the Maester CSV export take many minutes.
    $skippedCodes = @($countries | Where-Object { $collisions.ContainsKey($_) -and $_ -ne $homeCountry })
    $skippedPolicies = @($skippedCodes | ForEach-Object { $collisions[$_] } | Select-Object -Unique)
    $skippedText = ''
    if ($skippedCodes.Count -gt 0) {
        $shown = @($skippedCodes | Select-Object -First 8) -join ', '
        $more = if ($skippedCodes.Count -gt 8) { " and $($skippedCodes.Count - 8) more" } else { '' }
        $skippedText = " Skipped as home: $($skippedCodes.Count) countr$(if ($skippedCodes.Count -eq 1) { 'y' } else { 'ies' }) ($shown$more), matched by $(@($skippedPolicies | Select-Object -First 5) -join ', ')$(if ($skippedPolicies.Count -gt 5) { " and $($skippedPolicies.Count - 5) more" })."
    }
    $notes.Add("Home location: $homeCountry chosen as $homeWhy.$skippedText")
    $locations = [System.Collections.Generic.List[object]]::new()
    $locations.Add([pscustomobject]@{ Key = 'home'; Label = 'home'; Country = $homeCountry; IpAddress = $trustedIp })
    $outside = @('RU', 'NG', 'BR', 'VN', 'KP', 'IR') | Where-Object { $countries -notcontains $_ -and $_ -ne $homeCountry } | Select-Object -First 1
    $slots = [Math]::Max(0, $MaxLocations - 2)
    foreach ($country in ($countries | Where-Object { $_ -ne $homeCountry } | Select-Object -First $slots)) {
        $locations.Add([pscustomobject]@{ Key = "cc-$country"; Label = "named location country $country"; Country = [string]$country; IpAddress = $null })
    }
    # 203.0.113.0/24 is the RFC 5737 documentation range: an address that no tenant range should contain.
    $locations.Add([pscustomobject]@{ Key = 'outside'; Label = 'outside every named location'; Country = [string]$outside; IpAddress = $(if ($usesIpLocations) { '203.0.113.10' } else { $null }) })
    if ($usesIpLocations -and -not $trustedIp) { $notes.Add('The tenant has IP named locations but none is trusted with an IPv4 range, so the home scenarios carry no IP address.') }

    # User actions
    $actions = @($live | ForEach-Object { @($_.conditions.applications.includeUserActions) } |
            Where-Object { $_ -match 'registerSecurityInformation|registerOrJoinDevices' } |
            ForEach-Object { $_ -replace '^urn:user:', '' } | Select-Object -Unique)

    # Risk
    $risk = if ($P2Licensed -eq $true) { @('High') } else { @() }
    if ($P2Licensed -eq $true) {
        $notes.Add("Risk axes probed (Entra ID P2 present): service plan $P2ServicePlan was found among the enabled subscribed SKUs.")
    } elseif ($null -eq $P2Licensed) {
        $notes.Add("Risk axes omitted: Entra ID P2 not licensed (the tenant's subscribed SKUs could not be read, so service plan $P2ServicePlan could not be found and P2 is assumed absent). Policies that need a risk level are evaluated with risk None.")
    } else {
        $notes.Add("Risk axes omitted: Entra ID P2 not licensed (service plan $P2ServicePlan was not found among the enabled subscribed SKUs). Policies that need a risk level are evaluated with risk None.")
    }

    # Legacy probes: once per distinct policy path, not once per app.
    $legacyPolicies = @($live | Where-Object { $t = @($_.conditions.clientAppTypes); $t -contains 'exchangeActiveSync' -or $t -contains 'other' })
    $legacyIds = @($legacyPolicies | ForEach-Object { @($_.conditions.applications.includeApplications) } | Where-Object { $_ -match $guid } | Select-Object -Unique)
    $legacy = [System.Collections.Generic.List[object]]::new()
    $legacy.Add([pscustomobject]@{ AppKey = 'exo'; ClientTypes = @('exchangeActiveSync', 'other') })
    $legacy.Add([pscustomobject]@{ AppKey = 'spo'; ClientTypes = @('other') })
    foreach ($app in $apps) {
        if ($app.Key -in @('exo', 'spo')) { continue }
        if ($legacyIds -contains $app.Id) { $legacy.Add([pscustomobject]@{ AppKey = $app.Key; ClientTypes = @('other') }) }
    }
    $notes.Add("Legacy clients are probed once per distinct policy path: Exchange Online with exchangeActiveSync and other, SharePoint Online as the representative other application with other$(if ($legacy.Count -gt 2) { ", and the applications that legacy-client policies name explicitly ($((@($legacy | Select-Object -Skip 2) | ForEach-Object { $_.AppKey }) -join ', '))" }).")

    [pscustomobject]@{
        Apps             = $apps.ToArray()
        ClientTypes      = @('browser', 'mobileAppsAndDesktopClients', 'exchangeActiveSync', 'other')
        LegacyProbes     = $legacy.ToArray()
        Platforms        = @($platforms)
        Locations        = $locations.ToArray()
        UserActions      = @($actions)
        SignInRiskLevels = @($risk)
        UserRiskLevels   = @($risk)
        Notes            = $notes.ToArray()
    }
}
