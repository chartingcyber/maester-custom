function Get-ResCaOutcome {
    <#
    .SYNOPSIS
    Classifies the result of one What If evaluation.

    .DESCRIPTION
    Input is the list returned by Test-MtConditionalAccessWhatIf -AllResults. Only enforced policies (state
    enabled) that apply decide the Class; policies in report-only mode are classified separately.

    Class is one of Block, PhishingResistant, MFA, DeviceRequired, AppRequired, NoControl and NotAssessed.
    AppRequired means an approved client app or an app protection policy is required and nothing stronger. A row
    that carries resCaError (a What If call that failed after retries, from Invoke-ResCaWhatIf) is NotAssessed and
    Failure holds the reason. Every applying
    policy must be satisfied, so the flags of the applying policies are combined as a union (see
    Get-ResCaGrantFlag for how one policy's alternatives combine). A block anywhere is Block. A policy whose
    analysisReasons is notEnoughInformation, invalidCondition, invalidPolicy or unknownFutureValue could not be
    evaluated, and makes the Class NotAssessed unless an enforced block already decides it. The other reasons
    (users, application, location and so on) only say why a policy did not apply.

    A report-only block that is conditioned on a location (a geoblock being trialled) is listed under ReportOnly and
    ReportOnlyLocationBlock but is not counted when deciding whether coverage depends on report-only policies,
    because it says nothing about the controls of the signed-in user. Its conditions come from the result row, or
    from Policy (the tenant's policies, looked up by id) when the row has none.
    Returns Class, Flags, Enforced, ReportOnly, ReportOnlyClass, CoverageDependsOnReportOnly, NotAssessedPolicies,
    ReportOnlyLocationBlock, Failure and PhishingResistant (a boolean).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        # The evaluation results.
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]] $Result = @(),

        # The tenant's policies, to look up conditions that a result row does not carry.
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]] $Policy = @()
    )

    $notEvaluated = @('notEnoughInformation', 'invalidCondition', 'invalidPolicy', 'unknownFutureValue')
    $allRows = @($Result | Where-Object { $_ })
    $failure = @($allRows | Where-Object { $_.resCaError } | ForEach-Object { [string]$_.resCaError } | Select-Object -First 1)
    $rows = @($allRows | Where-Object { -not $_.resCaError })
    $live = @($rows | Where-Object { $_.state -in @('enabled', 'enabledForReportingButNotEnforced') })
    $enforced = @($live | Where-Object { $_.state -eq 'enabled' -and $_.policyApplies -eq $true })
    $reportOnly = @($live | Where-Object { $_.state -eq 'enabledForReportingButNotEnforced' -and $_.policyApplies -eq $true })
    $notAssessed = @($live | Where-Object { $_.analysisReasons -and $notEvaluated -contains [string]$_.analysisReasons })

    function Test-LocationConditioned {
        param($Row)
        $locations = $Row.conditions.locations
        if (-not $locations) {
            $match = @($Policy | Where-Object { $_ -and $_.id -eq $Row.id } | Select-Object -First 1)[0]
            $locations = $match.conditions.locations
        }
        if (-not $locations) { return $false }
        $include = @($locations.includeLocations | Where-Object { $_ })
        $exclude = @($locations.excludeLocations | Where-Object { $_ })
        ($include.Count -gt 0 -and -not ($include.Count -eq 1 -and $include[0] -eq 'All' -and $exclude.Count -eq 0))
    }
    function Get-PolicyClass {
        param($Policy)
        $flags = [System.Collections.Generic.List[string]]::new()
        foreach ($p in $Policy) { foreach ($f in @(Get-ResCaGrantFlag -GrantControl $p.grantControls)) { if ($f -notin $flags) { $flags.Add($f) } } }
        $class = if ($flags -contains 'Block') { 'Block' }
        elseif ($flags -contains 'PhishingResistant') { 'PhishingResistant' }
        elseif ($flags -contains 'MFA') { 'MFA' }
        elseif ($flags -contains 'Device') { 'DeviceRequired' }
        elseif ($flags -contains 'App') { 'AppRequired' }
        else { 'NoControl' }
        [pscustomobject]@{ Class = $class; Flags = $flags.ToArray() }
    }

    $enforcedResult = Get-PolicyClass -Policy $enforced
    $locationBlocks = @($reportOnly | Where-Object { (@($_.grantControls.builtInControls) -contains 'block') -and (Test-LocationConditioned -Row $_) })
    $reportCounted = @($reportOnly | Where-Object { $locationBlocks -notcontains $_ })
    $reportResult = Get-PolicyClass -Policy $reportCounted

    $class = $enforcedResult.Class
    if ($notAssessed.Count -gt 0 -and $class -ne 'Block') { $class = 'NotAssessed' }
    if ($failure.Count -gt 0) { $class = 'NotAssessed' }

    $rank = @{ NoControl = 0; AppRequired = 1; DeviceRequired = 2; MFA = 3; PhishingResistant = 4; Block = 5 }
    $reportBetter = ($reportResult.Class -ne 'NoControl') -and ($rank[$reportResult.Class] -gt $rank[$enforcedResult.Class])

    [pscustomobject]@{
        Class                       = $class
        Flags                       = $enforcedResult.Flags
        Enforced                    = $enforced
        ReportOnly                  = $reportOnly
        ReportOnlyClass             = $reportResult.Class
        CoverageDependsOnReportOnly = [bool]$reportBetter
        NotAssessedPolicies         = $notAssessed
        ReportOnlyLocationBlock     = $locationBlocks
        Failure                     = $(if ($failure.Count -gt 0) { $failure[0] } else { $null })
        PhishingResistant           = ($enforcedResult.Flags -contains 'PhishingResistant') -or ($enforcedResult.Class -eq 'Block')
    }
}
