function Resolve-ResCaAppName {
    <#
    .SYNOPSIS
    Turns application IDs into display names, with a cache.

    .DESCRIPTION
    Returns a hashtable of application ID to display name. The first-party applications of Get-ResCaWellKnownApp
    need no lookup. Any other ID is looked up once with Invoke-MtGraphRequest on
    servicePrincipals?$filter=appId eq '<id>' (Application.Read.All, which the pack already uses), and the answer,
    or the ID itself when nothing is found or the call fails, is kept in Cache, so a run makes at most one call per
    ID. Values that are not GUIDs (All, Office365, MicrosoftAdminPortals) map to themselves.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        # Application IDs (appId values).
        [AllowEmptyCollection()]
        [AllowNull()]
        [string[]] $AppId = @(),

        # A hashtable that keeps answers between calls.
        [hashtable] $Cache = @{}
    )

    $guid = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    $known = @{}
    foreach ($app in (Get-ResCaWellKnownApp)) { $known[[string]$app.Id] = [string]$app.Name }
    $names = @{}
    foreach ($id in @($AppId | Where-Object { $_ } | Select-Object -Unique)) {
        $key = 'appname:' + $id.ToLowerInvariant()
        if ($known.ContainsKey($id)) { $names[$id] = $known[$id]; continue }
        if ($id -notmatch $guid) { $names[$id] = $id; continue }
        if (-not $Cache.ContainsKey($key)) {
            $name = $id
            try {
                $found = @(Invoke-MtGraphRequest -RelativeUri 'servicePrincipals' -ApiVersion v1.0 -Filter "appId eq '$id'" -Select id, appId, displayName -ErrorAction Stop | Where-Object { $_ })
                if ($found.Count -gt 0 -and $found[0].displayName) { $name = [string]$found[0].displayName }
            } catch {
                Write-Verbose "Application $id could not be resolved: $($_.Exception.Message)"
            }
            $Cache[$key] = $name
        }
        $names[$id] = [string]$Cache[$key]
    }
    $names
}
