function Read-ResCaDesiredState {
    <#
    .SYNOPSIS
    Reads the optional desired-state JSON file that overrides the default expectations.

    .DESCRIPTION
    Returns the parsed object, or $null when no path is given. A path that does not exist or does not parse is an
    error, because silently falling back to the defaults would hide a typo.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        # Path of the desired-state JSON file.
        [AllowEmptyString()]
        [string] $Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "The desired-state file '$Path' does not exist." }
    try {
        Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -Depth 20
    } catch {
        throw "The desired-state file '$Path' is not valid JSON: $($_.Exception.Message)"
    }
}
