function Test-ResSecureScoreGaps {
    <#
    .SYNOPSIS
    Lists the Microsoft Secure Score recommendations with the most points still to gain.

    .DESCRIPTION
    Reads the latest Secure Score and the control profiles, and lists the controls that are not fully implemented,
    ordered by the points still to gain, with the user impact and implementation cost Microsoft assigns. This is an
    information check: it never fails. The result is Investigate when there are gaps to review. Use it to find
    controls that none of the other checks cover.
    #>
    [MaesterTest(
        Id           = 'MP.RESOURCIVE.3007',
        Title        = 'The Secure Score recommendations with the most points to gain are listed for review.',
        Product      = 'defender',
        Feature      = 'exposure-management',
        Area         = 'infrastructure',
        ResourceType = 'Tenant',
        Severity     = 'Info',
        Mitre        = 'None',
        Service      = 'Graph',
        Permission   = 'Graph:Scope:SecurityEvents.Read.All'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        # How many recommendations to list.
        [ValidateRange(1, 100)]
        [int] $Top = 15
    )

    try {
        $scores = @(Invoke-MtGraphRequest -RelativeUri 'security/secureScores?$top=1' -ApiVersion v1.0 -ErrorAction Stop)
        $profiles = @(Invoke-MtGraphRequest -RelativeUri 'security/secureScoreControlProfiles' -ApiVersion v1.0 -ErrorAction Stop)
    } catch {
        Resolve-ResGraphError -ErrorRecord $_ -Feature 'Secure Score' -Requires 'SecurityEvents.Read.All'
    }

    if ($scores.Count -eq 0) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason 'Not assessed: the tenant has no Secure Score yet.'
    }
    $latest = $scores[0]
    $byName = @{}
    foreach ($control in @($latest.controlScores)) { $byName[[string]$control.controlName] = $control }

    $gaps = foreach ($profile in $profiles) {
        if ($profile.deprecated) { continue }
        $max = [double]$profile.maxScore
        if ($max -le 0) { continue }
        $control = $byName[[string]$profile.id]
        $current = if ($control) { [double]$control.score } else { 0 }
        if ($current -ge $max) { continue }
        [pscustomobject]@{
            Title  = [string]$profile.title
            Service = [string]$profile.service
            Gain   = [math]::Round($max - $current, 1)
            Impact = [string]$profile.userImpact
            Cost   = [string]$profile.implementationCost
            Tier   = [string]$profile.tier
        }
    }
    $gaps = @($gaps | Sort-Object Gain -Descending)

    $asOf = "$($latest.createdDateTime)"
    $header = "Secure Score $($latest.currentScore) of $($latest.maxScore) as of $asOf."
    if ($gaps.Count -eq 0) {
        Add-MtTestResultDetail -Result "$header Every control is fully implemented."
        return $true
    }
    $table = "| Recommendation | Service | Points to gain | User impact | Implementation cost |`n| --- | --- | --- | --- | --- |`n" +
        ((@($gaps) | Select-Object -First $Top | ForEach-Object { "| $($_.Title) | $($_.Service) | $($_.Gain) | $($_.Impact) | $($_.Cost) |" }) -join "`n")
    Add-MtTestResultDetail -Result "$header $($gaps.Count) control(s) are not fully implemented. The $Top with the most points to gain:`n`n$table" -Investigate
    return $true
}
