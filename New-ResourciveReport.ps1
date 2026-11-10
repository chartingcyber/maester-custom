#Requires -Version 7.4
<#
.SYNOPSIS
Builds a single-file HTML findings report from a Maester result, ordered by risk.

.DESCRIPTION
Reads assessment.json (from Invoke-Maester or Invoke-ResourciveAssessment.ps1) and writes one self-contained HTML
file that works offline, plus an action list as CSV. Findings are ranked by risk and effort using
resourcive-report/risk-model.json, which you can edit.

The report has: an overview with a score; a roadmap (now, next, later); every finding ranked; findings grouped by
the attack they let through; framework views (CIS Level 1 and 2, CISA SCuBA, NIST 800-53, MITRE ATT&CK); scores by
area; an inventory of privileged accounts; licence gaps; changes since the previous run of the same tenant; and
everything that could not be assessed and why.

Nothing is sent anywhere. Email addresses are shown in full, because an administrator inventory is only useful when
you can tell who the accounts are. Use -MaskNames before sharing the file outside the people who run the tenant: it
keeps the first three characters of each address (joh***@contoso.com). Device names and IP addresses are not masked.

How the numbers are made:
 - Each failed check has a risk: severity weight x area multiplier (risk-model.json).
 - Effort is the check's implementation cost plus its user impact. Priority is risk divided by effort.
 - Roadmap: Now = quick wins (high risk, low effort). Next = other failures of medium or higher risk and modest
   effort. Later = every other failure. The cut-offs are in risk-model.json.
 - The score is the weighted share of assessed checks that passed. Checks that were skipped, errored or need a
   person to review are left out of the score and listed under "Not assessed", never counted as passed.
 - A check that expands into many scenarios (such as the Conditional Access What-If scenarios) is one finding, with
   the scenario counts shown.
 - Attack paths are assigned from each check's MITRE ATT&CK techniques, then its area (risk-model.json).

.PARAMETER ResultPath
A results folder or an assessment.json file.

.PARAMETER OutputPath
Where to write the HTML. Default: findings-report.html beside the result.

.PARAMETER Title
Report title. Default: the tenant name from the result.

.PARAMETER SummaryPath
Optional text or markdown file whose content replaces the generated summary on the first page. Use it for your own
analysis of the tenant.

.PARAMETER ComparePath
An earlier results folder or assessment.json of the same tenant, to show what changed. Default: the latest earlier
run of the same tenant found beside this one.

.PARAMETER NoCompare
Do not look for an earlier run.

.PARAMETER MaskNames
Mask email addresses, keeping the first three characters of each, for a copy that leaves the team.

.EXAMPLE
./New-ResourciveReport.ps1 -ResultPath ./test-results/contoso.com_20261109-174608
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ResultPath,
    [string] $OutputPath,
    [string] $Title,
    [string] $SummaryPath,
    [string] $ComparePath,
    [switch] $NoCompare,
    [switch] $MaskNames
)

$ErrorActionPreference = 'Stop'

$jsonPath = if (Test-Path -LiteralPath $ResultPath -PathType Container) { Join-Path $ResultPath 'assessment.json' } else { $ResultPath }
if (-not (Test-Path -LiteralPath $jsonPath)) { throw "No assessment.json found at '$ResultPath'." }
$resultDir = Split-Path (Resolve-Path -LiteralPath $jsonPath).Path -Parent
if (-not $OutputPath) { $OutputPath = Join-Path $resultDir 'findings-report.html' }

$modelPath = Join-Path $PSScriptRoot 'resourcive-report/risk-model.json'
$templatePath = Join-Path $PSScriptRoot 'resourcive-report/report-template.html'
$model = Get-Content -LiteralPath $modelPath -Raw | ConvertFrom-Json -AsHashtable
$result = Get-Content -LiteralPath $jsonPath -Raw | ConvertFrom-Json -Depth 30

function Get-Weight($table, $key, $default) {
    if ($null -ne $key -and $table.ContainsKey([string]$key)) { [double]$table[[string]$key] } else { [double]$default }
}

function Hide-Email([string] $Text) {
    if (-not $MaskNames -or -not $Text) { return $Text }
    [regex]::Replace($Text, '(?<![\w.+-])([A-Za-z0-9_]{1,3})[A-Za-z0-9._+\-#%]*@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})', '$1***@$2')
}

function Limit([string] $Text, [int] $Max) {
    if (-not $Text) { return '' }
    if ($Text.Length -le $Max) { return $Text }
    $Text.Substring(0, $Max) + "`n`n*(shortened; the full text is in assessment.json)*"
}

function Get-NotAssessedKind($test) {
    $reason = [string]$test.ReasonCode
    $detail = [string]$test.ReasonDetail
    if ($test.Result -eq 'NotRun') { return 'NotRun' }
    if ($test.Result -eq 'Error') { return 'Error' }
    if ($test.Result -eq 'Investigate') { return 'Investigate' }
    if ($reason -eq 'LicenseNotFound' -or $detail -match 'requires (one of these licen|Entra ID P2|Microsoft Defender)|licensed for Entra ID P2|not licensed') { return 'Licence' }
    if ($reason -eq 'ServiceNotConnected') { return 'NotConnected' }
    if ($reason -eq 'NoInstances' -or $detail -match 'deprecated|only for federal|Not available for API validation|not applicable|not enabled|nothing in this tenant') { return 'NotApplicable' }
    if ($detail -match 'not authorized|authoriz|Not assessed|Unable|could not') { return 'Access' }
    return 'Other'
}

function ConvertFrom-MarkdownTable([string] $Markdown) {
    $tables = [System.Collections.Generic.List[object]]::new()
    $lines = @($Markdown -split "`r?`n")
    $title = ''
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^\*\*(.+?)\*\*\s*$') { $title = $Matches[1] }
        if ($lines[$i] -match '^\s*\|' -and ($i + 1) -lt $lines.Count -and $lines[$i + 1] -match '^\s*\|[\s:|-]+\|\s*$') {
            $headers = @($lines[$i].Trim().Trim('|').Split('|') | ForEach-Object { $_.Trim() })
            $i += 2
            $tableRows = [System.Collections.Generic.List[object]]::new()
            while ($i -lt $lines.Count -and $lines[$i] -match '^\s*\|') {
                $tableRows.Add(@($lines[$i].Trim().Trim('|').Split('|') | ForEach-Object { Hide-Email $_.Trim() }))
                $i++
            }
            $i--
            $tables.Add([pscustomobject]@{ title = $title; headers = $headers; rows = @($tableRows) })
            $title = ''
        }
    }
    $tables
}

function Get-AttackPath($area, $mitre) {
    $best = $null; $bestCount = 0
    foreach ($path in $model.AttackPaths) {
        $count = 0
        foreach ($technique in $mitre) { foreach ($prefix in $path.mitre) { if ($technique -like "$prefix*") { $count++; break } } }
        if ($count -gt $bestCount) { $best = $path; $bestCount = $count }
    }
    if ($best) { return $best.id }
    foreach ($path in $model.AttackPaths) { if ($area -in $path.areas) { return $path.id } }
    'hygiene'
}

# One finding per test; scenario families (tests with a ParentId) become one finding.
function Get-ReportRows($tests) {
    $findings = [System.Collections.Generic.List[object]]::new()
    $families = $tests | Where-Object { $_.ParentId -and $_.Result -ne 'NotRun' } | Group-Object ParentId
    foreach ($test in ($tests | Where-Object { -not $_.ParentId -and $_.Result -ne 'NotRun' })) {
        $findings.Add([pscustomobject]@{ Test = $test; Family = $null })
    }
    foreach ($family in $families) {
        $children = @($family.Group)
        $failed = @($children | Where-Object Result -eq 'Failed')
        $pick = if ($failed.Count -gt 0) { $failed[0] } else { $children[0] }
        $sevRank = @{ Critical = 5; High = 4; Medium = 3; Low = 2; Info = 1 }
        $worst = ($children | Sort-Object { $sevRank[[string]$_.Severity] } -Descending | Select-Object -First 1)
        $summary = [pscustomobject]@{
            total       = $children.Count
            failed      = $failed.Count
            passed      = @($children | Where-Object Result -eq 'Passed').Count
            investigate = @($children | Where-Object Result -eq 'Investigate').Count
            skipped     = @($children | Where-Object Result -in 'Skipped', 'Error').Count
            examples    = @($failed | Select-Object -First 12 | ForEach-Object { Hide-Email ([string]$_.Title) })
        }
        $overall = if ($summary.failed -gt 0) { 'Failed' } elseif ($summary.passed -gt 0) { 'Passed' } elseif ($summary.investigate -gt 0) { 'Investigate' } else { 'Skipped' }
        $findings.Add([pscustomobject]@{ Test = $pick; Family = $summary; FamilyId = $family.Name; Overall = $overall; Worst = $worst })
    }

    $quick = $model.QuickWin
    $road = $model.Roadmap
    foreach ($item in $findings) {
        $t = $item.Test
        $isFamily = $null -ne $item.Family
        $id = if ($isFamily) { [string]$item.FamilyId } else { [string]$t.Id }
        $severity = if ($isFamily) { [string]$item.Worst.Severity } else { [string]$t.Severity }
        if (-not $severity) { $severity = 'Medium' }
        $area = [string]$t.Area
        $risk = (Get-Weight $model.SeverityWeight $severity 4) * (Get-Weight $model.AreaMultiplier $area 1)
        $effort = (Get-Weight $model.CostEffort ([string]$t.ImplementationCost) 2) + (Get-Weight $model.ImpactEffort ([string]$t.UserImpact) 1)
        if ($effort -lt 1) { $effort = 1 }
        $outcome = if ($isFamily) { $item.Overall } else { [string]$t.Result }
        $detail = [string]$t.ResultDetail.TestResult
        $findingTitle = [string]$t.Title
        if ($isFamily) {
            $findingTitle = if ($id -eq 'MP.RESOURCIVE.CA') { 'Conditional Access gives the expected outcome for sign-in scenarios (What-If)' } else { ([string]$t.Title) -replace '\s*\(.*$', '' }
            $detail = ''
        }
        $kind = if ($outcome -in 'Passed', 'Failed') { '' } else { Get-NotAssessedKind $t }

        # Maester's PIM alert checks (MT.1029 to MT.1032 and the like) print Microsoft's own count for the whole alert
        # ("13 user(s) ...") but list only the assignments left after filtering to Control Plane roles and removing
        # emergency-access accounts. Say so, so a short list is not read as a missing one.
        if ($detail -match '^\s*(\d+)\s+user\(s\)') {
            $claimed = [int]$Matches[1]
            $listed = ([regex]::Matches($detail, '(?m)^\s+-\s+')).Count
            if ($listed -gt 0 -and $listed -lt $claimed) {
                $detail = "**Note:** Microsoft's PIM alert counts $claimed assignments across all roles. This check counts only the $listed that hold Control Plane roles, leaving out emergency-access accounts, and only those are listed and cause the failure. The other $($claimed - $listed) are not named in the results; see the PIM alert in the Azure portal for the full list.`n`n$detail"
            }
        }

        # Split the description into "what it checks" and "how to fix it".
        $description = [string]$t.ResultDetail.TestDescription
        $fix = ''
        $fixAt = $description.IndexOf('#### Remediation action')
        if ($fixAt -ge 0) {
            $fix = $description.Substring($fixAt) -replace '^#### Remediation action\s*', ''
            $related = $fix.IndexOf('#### Related links')
            if ($related -ge 0) { $fix = $fix.Substring(0, $related) }
            $description = $description.Substring(0, $fixAt)
        }

        $mitre = @($t.Mitre | Where-Object { $_ -and $_ -ne 'None' })
        $controls = @($t.Control | Where-Object { $_ -and $_ -ne 'None' })
        $bench = $t.Benchmark
        $cis = $null; $cisa = $null
        if ($bench -and $bench.Framework -eq 'cis-m365') {
            $cis = [ordered]@{ req = [string]$bench.Requirement; level = [string]$bench.Level; profile = @($bench.Profile) -join ', ' }
        } elseif ($bench -and $bench.Framework -eq 'cisa-scuba') {
            $cisa = [ordered]@{ req = [string]$bench.Requirement; criticality = [string]$bench.Criticality }
        }
        $nist = @($controls | Where-Object { $_ -like 'nist-800-53-r5:*' } | ForEach-Object { ($_ -replace '^nist-800-53-r5:', '') })

        $isFail = ($outcome -eq 'Failed' -and $severity -ne 'Info')
        $isQuick = ($isFail -and $risk -ge $quick.MinRisk -and $effort -le $quick.MaxEffort)
        $band = if (-not $isFail) { '' } elseif ($isQuick) { 'now' } elseif ($risk -ge $road.NextMinRisk -and $effort -le $road.NextMaxEffort) { 'next' } else { 'later' }

        [pscustomobject][ordered]@{
            id       = $id
            title    = Hide-Email $findingTitle
            result   = $outcome
            severity = $severity
            area     = $area
            areaName = $(if ($model.AreaLabel.ContainsKey($area)) { $model.AreaLabel[$area] } else { $area })
            product  = [string]$t.Product
            domain   = $(if ($model.ProductLabel.ContainsKey([string]$t.Product)) { $model.ProductLabel[[string]$t.Product] } else { [string]$t.Product })
            cost     = [string]$t.ImplementationCost
            impact   = [string]$t.UserImpact
            risk     = [math]::Round($risk, 1)
            effort   = $effort
            priority = [math]::Round($risk / $effort, 2)
            quick    = $isQuick
            band     = $band
            path     = (Get-AttackPath $area $mitre)
            mitre    = $mitre
            controls = @($controls | Where-Object { $_ -notlike 'nist-800-53-r5:*' })
            nist     = $nist
            cis      = $cis
            cisa     = $cisa
            source   = [string]$t.Source
            suite    = [string]$t.Suite
            kind     = $kind
            reason   = Hide-Email ([string]$t.ReasonDetail)
            desc     = Hide-Email (Limit $description 1800)
            fix      = Hide-Email (Limit $fix 1800)
            detail   = Hide-Email (Limit $detail 3500)
            family   = $item.Family
            change   = ''
        }
    }
}

function Get-Score($set) {
    $passed = 0.0; $failed = 0.0
    foreach ($r in $set) {
        $w = $r.risk
        if ($w -le 0) { continue }
        if ($r.result -eq 'Passed') { $passed += $w } elseif ($r.result -eq 'Failed') { $failed += $w }
    }
    if (($passed + $failed) -eq 0) { return $null }
    [math]::Round(100 * $passed / ($passed + $failed), 0)
}

$tests = @($result.Tests)
$rows = @(Get-ReportRows $tests)

# Rows that never ran (opt-in services, previews), counted only.
$notRun = @($tests | Where-Object Result -eq 'NotRun')
$notRunGroups = @($notRun | Group-Object { if ($_.ReasonCode -eq 'OptInServiceNotConnected') { "Optional service not connected: $($_.Product)" } else { "$($_.ReasonCode)" } } | Sort-Object Count -Descending | ForEach-Object { [pscustomobject]@{ label = $_.Name; count = $_.Count } })

# ---- Changes since the previous run of this tenant ----
$changes = $null
$previousJson = $null
if (-not $NoCompare) {
    if ($ComparePath) {
        $previousJson = if (Test-Path -LiteralPath $ComparePath -PathType Container) { Join-Path $ComparePath 'assessment.json' } else { $ComparePath }
    } else {
        $current = [datetime]$result.ExecutedAt
        $parent = Split-Path $resultDir -Parent
        $prefix = (Split-Path $resultDir -Leaf) -replace '_\d{8}-\d{6}$', ''
        $best = $null; $bestAt = [datetime]::MinValue
        foreach ($dir in (Get-ChildItem -LiteralPath $parent -Directory -ErrorAction SilentlyContinue | Where-Object { $_.FullName -ne $resultDir -and ($_.Name -eq $prefix -or $_.Name -like "${prefix}_*") })) {
            $candidate = Join-Path $dir.FullName 'assessment.json'
            if (-not (Test-Path -LiteralPath $candidate)) { continue }
            try {
                $head = Get-Content -LiteralPath $candidate -Raw | ConvertFrom-Json -Depth 30
                $at = [datetime]$head.ExecutedAt
                if ($head.TenantId -eq $result.TenantId -and $at -lt $current -and $at -gt $bestAt) { $best = $candidate; $bestAt = $at }
            } catch { }
        }
        $previousJson = $best
    }
}
if ($previousJson -and (Test-Path -LiteralPath $previousJson)) {
    $previous = Get-Content -LiteralPath $previousJson -Raw | ConvertFrom-Json -Depth 30
    $previousRows = @(Get-ReportRows @($previous.Tests))
    $before = @{}
    foreach ($p in $previousRows) { $before[$p.id] = $p }
    foreach ($r in $rows) {
        $p = $before[$r.id]
        $r.change = if (-not $p) { 'new' }
        elseif ($p.result -eq 'Passed' -and $r.result -eq 'Failed') { 'regressed' }
        elseif ($p.result -eq 'Failed' -and $r.result -eq 'Passed') { 'fixed' }
        elseif ($p.result -eq 'Failed' -and $r.result -eq 'Failed') { 'still' }
        elseif ($p.result -ne $r.result) { 'changed' }
        else { 'same' }
    }
    $changes = [ordered]@{
        previousAt     = [string]$previous.ExecutedAt
        previousScore  = Get-Score $previousRows
        previousFailed = @($previousRows | Where-Object { $_.result -eq 'Failed' -and $_.severity -ne 'Info' }).Count
        regressed      = @($rows | Where-Object change -eq 'regressed' | ForEach-Object id)
        fixed          = @($rows | Where-Object change -eq 'fixed' | ForEach-Object id)
        newChecks      = @($rows | Where-Object change -eq 'new' | ForEach-Object id)
        still          = @($rows | Where-Object change -eq 'still' | ForEach-Object id)
        changed        = @($rows | Where-Object change -eq 'changed' | ForEach-Object id)
        note           = 'Compared by check ID. Checks added since the earlier run show as new; a change of code between runs can also change a result.'
    }
}

# ---- Score, domains, severities ----
$assessed = @($rows | Where-Object { $_.result -in 'Passed', 'Failed' })
$inScopeNotAssessed = @($rows | Where-Object { $_.result -notin 'Passed', 'Failed' -and $_.kind -notin 'NotConnected', 'NotApplicable' })
$coverage = if (($assessed.Count + $inScopeNotAssessed.Count) -gt 0) { [math]::Round(100 * $assessed.Count / ($assessed.Count + $inScopeNotAssessed.Count), 0) } else { $null }

$domains = @($rows | Group-Object domain | ForEach-Object {
        $set = @($_.Group)
        [pscustomobject]@{
            name        = $_.Name
            score       = Get-Score $set
            passed      = @($set | Where-Object result -eq 'Passed').Count
            failed      = @($set | Where-Object { $_.result -eq 'Failed' -and $_.severity -ne 'Info' }).Count
            notAssessed = @($set | Where-Object { $_.result -notin 'Passed', 'Failed' -and $_.kind -notin 'NotConnected', 'NotApplicable' }).Count
        }
    } | Where-Object { $_.passed + $_.failed + $_.notAssessed -gt 0 } | Sort-Object { if ($null -eq $_.score) { 101 } else { $_.score } })

$failedReal = @($rows | Where-Object { $_.result -eq 'Failed' -and $_.severity -ne 'Info' })
$severityCounts = [ordered]@{}
foreach ($s in 'Critical', 'High', 'Medium', 'Low') { $severityCounts[$s] = @($failedReal | Where-Object severity -eq $s).Count }
$overallScore = Get-Score $rows
$topRisks = @($failedReal | Sort-Object risk -Descending | Select-Object -First 5)
$quickWins = @($rows | Where-Object quick | Sort-Object priority -Descending)
$bands = [ordered]@{ now = @($failedReal | Where-Object band -eq 'now').Count; next = @($failedReal | Where-Object band -eq 'next').Count; later = @($failedReal | Where-Object band -eq 'later').Count }

# ---- Attack paths ----
$paths = @(foreach ($path in $model.AttackPaths) {
        $set = @($rows | Where-Object { $_.path -eq $path.id })
        $fails = @($set | Where-Object { $_.result -eq 'Failed' -and $_.severity -ne 'Info' })
        if ($set.Count -eq 0) { continue }
        [pscustomobject]@{
            id      = $path.id
            name    = $path.name
            summary = $path.summary
            total   = $set.Count
            passed  = @($set | Where-Object result -eq 'Passed').Count
            failed  = $fails.Count
            risk    = [math]::Round(($fails | Measure-Object risk -Sum).Sum, 0)
            quick   = @($fails | Where-Object quick).Count
            score   = Get-Score $set
        }
    })

# ---- Frameworks ----
function Get-RequirementState($set) {
    if (@($set | Where-Object result -eq 'Failed').Count -gt 0) { return 'Failed' }
    if (@($set | Where-Object result -eq 'Passed').Count -gt 0) { return 'Passed' }
    return 'Not assessed'
}

$cisFile = Join-Path $PSScriptRoot 'tests/cis/frameworks/cis-m365.json'
$cisCatalog = if (Test-Path -LiteralPath $cisFile) { Get-Content -LiteralPath $cisFile -Raw | ConvertFrom-Json } else { $null }
$tmp = @(foreach ($group in ($rows | Where-Object { $_.cis } | Group-Object { $_.cis.req })) {
        $first = $group.Group[0]
        [pscustomobject]@{
            req      = $group.Name
            level    = $first.cis.level
            profile  = $first.cis.profile
            section  = ($group.Name -split '\.')[0]
            state    = Get-RequirementState $group.Group
            ids      = @($group.Group | ForEach-Object id)
            title    = $first.title
            severity = $first.severity
        }
    })
$cisRows = @($tmp | Sort-Object { [version]($_.req -replace '[^\d.]', '' -replace '\.$', '') })
$cisSummary = [ordered]@{ version = $(if ($cisCatalog) { [string]$cisCatalog.Version } else { '' }); sections = $model.CisSections; levels = [ordered]@{} }
foreach ($level in 'L1', 'L2') {
    $set = @($cisRows | Where-Object level -eq $level)
    $cisSummary.levels[$level] = [ordered]@{
        inBenchmark = $(if ($cisCatalog) { @($cisCatalog.Requirements | Where-Object Level -eq $level).Count } else { $null })
        checked     = $set.Count
        passed      = @($set | Where-Object state -eq 'Passed').Count
        failed      = @($set | Where-Object state -eq 'Failed').Count
        notAssessed = @($set | Where-Object state -eq 'Not assessed').Count
    }
}
$cisSummary.rows = $cisRows

$tmp = @(foreach ($group in ($rows | Where-Object { $_.cisa } | Group-Object { $_.cisa.req })) {
        $first = $group.Group[0]
        [pscustomobject]@{ req = $group.Name; area = (($group.Name -split '\.')[0..1] -join '.'); criticality = $first.cisa.criticality; state = Get-RequirementState $group.Group; title = $first.title; ids = @($group.Group | ForEach-Object id) }
    })
$cisaRows = @($tmp | Sort-Object req)

$tmp = @(foreach ($family in ($rows | ForEach-Object { $r = $_; $r.nist | ForEach-Object { [pscustomobject]@{ family = (($_ -split '[-(]')[0]); row = $r } } } | Group-Object family)) {
        $set = @($family.Group | ForEach-Object { $_.row } | Sort-Object id -Unique)
        [pscustomobject]@{ family = $family.Name; passed = @($set | Where-Object result -eq 'Passed').Count; failed = @($set | Where-Object { $_.result -eq 'Failed' -and $_.severity -ne 'Info' }).Count; notAssessed = @($set | Where-Object { $_.result -notin 'Passed', 'Failed' }).Count }
    })
$nistRows = @($tmp | Sort-Object failed -Descending)

$tmp = @(foreach ($technique in ($rows | ForEach-Object { $r = $_; $r.mitre | ForEach-Object { [pscustomobject]@{ technique = $_; row = $r } } } | Group-Object technique)) {
        $set = @($technique.Group | ForEach-Object { $_.row } | Sort-Object id -Unique)
        [pscustomobject]@{ technique = $technique.Name; passed = @($set | Where-Object result -eq 'Passed').Count; failed = @($set | Where-Object { $_.result -eq 'Failed' -and $_.severity -ne 'Info' }).Count; notAssessed = @($set | Where-Object { $_.result -notin 'Passed', 'Failed' }).Count }
    })
$mitreRows = @($tmp | Sort-Object failed -Descending | Select-Object -First 40)

$frameworks = [ordered]@{ cis = $cisSummary; cisa = $cisaRows; nist = $nistRows; mitre = $mitreRows }

# ---- Licences ----
$planNames = @($result.TenantContext.Licenses.ServicePlanNames)
$licenceKnown = ($result.TenantContext.Licenses.State -eq 'Known')
$gapMap = @{}
foreach ($r in ($rows | Where-Object { $_.result -notin 'Passed', 'Failed' })) {
    $text = if ($r.reason) { $r.reason } else { Limit $r.detail 500 }
    $codes = @()
    if ($text -match 'licen[cs]es?: ([A-Za-z0-9_, ]+?)\.') { $codes = @($Matches[1] -split ',\s*' | Where-Object { $_ }) }
    elseif ($text -match 'Entra ID P2|Entra ID Governance') { $codes = @('AAD_PREMIUM_P2') }
    foreach ($code in $codes) {
        if (-not $gapMap.ContainsKey($code)) { $gapMap[$code] = [System.Collections.Generic.List[string]]::new() }
        if ($r.id -notin $gapMap[$code]) { $gapMap[$code].Add($r.id) }
    }
}
$catalog = @($model.LicenceCatalog | ForEach-Object {
        [pscustomobject]@{ code = $_.code; name = $_.name; unlocks = $_.unlocks; present = $(if ($licenceKnown) { [bool]($_.code -in $planNames) } else { $null }); blocked = @($(if ($gapMap.ContainsKey($_.code)) { $gapMap[$_.code] })) }
    })
$knownCodes = @($model.LicenceCatalog | ForEach-Object { $_.code })
$otherGaps = @($gapMap.Keys | Where-Object { $_ -notin $knownCodes } | ForEach-Object { [pscustomobject]@{ code = $_; name = $_; unlocks = ''; present = $null; blocked = @($gapMap[$_]) } })
$licences = [ordered]@{ known = $licenceKnown; catalog = @($catalog + $otherGaps) }

# ---- Secure Score (from check 3007) ----
$secureScore = $null
$ss = $tests | Where-Object { $_.Id -eq 'MP.RESOURCIVE.3007' } | Select-Object -First 1
if ($ss -and ([string]$ss.ResultDetail.TestResult) -match 'Secure Score ([\d.]+) of ([\d.]+)') { $secureScore = [ordered]@{ current = [double]$Matches[1]; max = [double]$Matches[2] } }

# ---- Admin inventory: check 3010 when the run has it, otherwise the privileged-user table of 3002 ----
$admins = $null
foreach ($adminId in 'MP.RESOURCIVE.3010', 'MP.RESOURCIVE.3002') {
    $adminTest = $tests | Where-Object { $_.Id -eq $adminId -and $_.Result -in 'Investigate', 'Passed', 'Failed' } | Select-Object -First 1
    if (-not $adminTest) { continue }
    $text = [string]$adminTest.ResultDetail.TestResult
    $parsed = @(ConvertFrom-MarkdownTable $text)
    if ($parsed.Count -eq 0) { continue }
    $firstParagraph = (($text.Trim() -split "`r?`n`r?`n")[0]) -replace '\s+', ' '
    $admins = [ordered]@{
        source  = $adminId
        full    = ($adminId -eq 'MP.RESOURCIVE.3010')
        summary = Hide-Email $firstParagraph
        tables  = @($parsed | ForEach-Object { if ($adminId -eq 'MP.RESOURCIVE.3002' -and -not $_.title) { $_.title = 'Accounts' }; $_ })
    }
    break
}


# ---- Conditional Access scenarios (expected against observed) ----
function Get-CaCell([string] $Text, [string] $Label) {
    $m = [regex]::Match($Text, "(?m)^\| $([regex]::Escape($Label)) \| (.*?) \|\s*$")
    if ($m.Success) { $m.Groups[1].Value } else { '' }
}
function Get-CaPolicyName([string] $Text, [string] $Header) {
    $i = $Text.IndexOf($Header)
    if ($i -lt 0) { return @() }
    $rest = $Text.Substring($i + $Header.Length)
    $stop = [regex]::Match($rest, '(?m)^(\*\*|Why this is expected|>)')
    if ($stop.Success) { $rest = $rest.Substring(0, $stop.Index) }
    @([regex]::Matches($rest, '(?m)^\| (.+?) \|') | ForEach-Object { $_.Groups[1].Value } | Where-Object { $_ -notin 'Policy', '---' -and $_ -notmatch '^-+$' })
}
$caScenarios = @(foreach ($t in ($tests | Where-Object { $_.ParentId -eq 'MP.RESOURCIVE.CA' -and $_.Result -ne 'NotRun' })) {
        $text = [string]$t.ResultDetail.TestResult
        $personaCell = Get-CaCell $text 'Persona'
        $pm = [regex]::Match($personaCell, '^(.*) \((\S+?)\)$')
        $persona = if ($pm.Success) { $pm.Groups[1].Value } else { $personaCell }
        $classLabel = if ($pm.Success) { $pm.Groups[2].Value } else { '' }
        $classCell = Get-CaCell $text 'Persona class'
        $users = if ($classCell -match '^(\d+) users?') { [int]$Matches[1] } else { 1 }
        $included = @(); $excluded = @()
        if ($classCell -match 'included by: (.*?)(?:; excluded by: (.*))?$') {
            $included = @($Matches[1] -split ', ' | Where-Object { $_ -and $_ -ne 'none' })
            if ($Matches[2]) { $excluded = @($Matches[2] -split ', ' | Where-Object { $_ -and $_ -ne 'none' }) }
        }
        $app = (Get-CaCell $text 'Signs in to') -replace ' \([0-9a-f-]{36}\)$', ''
        $expectation = Get-CaCell $text 'Expectation'
        $why = [regex]::Match($text, '(?m)^Why this is expected: (.*)$')
        [pscustomobject][ordered]@{
            id         = [string]$t.Id
            result     = [string]$t.Result
            severity   = [string]$t.Severity
            persona    = Hide-Email $persona
            roles      = @((Get-CaCell $text 'Privileged roles') -split ',\s*' | Where-Object { $_ })
            roleLabel  = if ($classLabel -like 'Privileged:*') { ($classLabel -replace '^Privileged:', '') } else { '' }
            kind       = ($classLabel -split ':')[0]
            class      = $classLabel
            users      = $users
            included   = @($included | ForEach-Object { Hide-Email $_ })
            excluded   = @($excluded | ForEach-Object { Hide-Email $_ })
            app        = $app
            client     = Get-CaCell $text 'Client app type'
            platform   = Get-CaCell $text 'Device platform'
            location   = Get-CaCell $text 'Location'
            risk       = Get-CaCell $text 'Sign-in risk / user risk'
            observed   = Get-CaCell $text 'Observed outcome'
            expected   = (($expectation -split ' \(')[0])
            expectNote = $expectation
            why        = if ($why.Success) { Hide-Email $why.Groups[1].Value } else { '' }
            enforced   = @(Get-CaPolicyName $text '**Enforced policies that applied**' | ForEach-Object { Hide-Email $_ })
            reportOnly = @(Get-CaPolicyName $text '**Report-only policies that applied**' | ForEach-Object { Hide-Email $_ })
        }
    })

# ---- Summary text ----
$weakest = @($domains | Where-Object { $null -ne $_.score } | Select-Object -First 2)
$generated = @()
$generated += "$($failedReal.Count) of $($assessed.Count) assessed checks failed. $($severityCounts.Critical) are Critical and $($severityCounts.High) are High."
if ($weakest.Count -gt 0) { $generated += "The lowest-scoring areas are $(($weakest | ForEach-Object { "$($_.name) ($($_.score))" }) -join ' and ')." }
if ($quickWins.Count -gt 0) { $generated += "$($quickWins.Count) failing checks are quick wins: high risk, little effort and little user impact. They make up the Now column of the roadmap." }
if ($coverage -ne $null -and $coverage -lt 100) { $generated += "Coverage is $coverage%: $($inScopeNotAssessed.Count) in-scope checks could not be assessed, listed on the Not assessed tab. They are not counted as passed." }
if ($changes) {
    $delta = if ($null -ne $overallScore -and $null -ne $changes.previousScore) { $overallScore - $changes.previousScore } else { $null }
    $generated += "Since the previous run: $($changes.fixed.Count) checks now pass and $($changes.regressed.Count) newly fail$(if ($null -ne $delta) { ", and the score moved from $($changes.previousScore) to $overallScore" })."
}
$summaryText = if ($SummaryPath) { Get-Content -LiteralPath $SummaryPath -Raw } else { $generated -join "`n`n" }

$data = [ordered]@{
    meta        = [ordered]@{
        title      = $(if ($Title) { $Title } else { [string]$result.TenantName })
        tenantName = [string]$result.TenantName
        tenantId   = [string]$result.TenantId
        account    = Hide-Email ([string]$result.Account)
        executedAt = [string]$result.ExecutedAt
        duration   = [string]$result.TotalDuration
        version    = [string]$result.LatestVersion
        masked     = [bool]$MaskNames
        generated  = (Get-Date).ToString('yyyy-MM-dd HH:mm')
    }
    score       = $overallScore
    coverage    = $coverage
    secureScore = $secureScore
    counts      = [ordered]@{ passed = $assessed.Count - $failedReal.Count; failed = $failedReal.Count; investigate = @($rows | Where-Object result -eq 'Investigate').Count; skipped = @($rows | Where-Object result -eq 'Skipped').Count; errors = @($rows | Where-Object result -eq 'Error').Count; notRun = $notRun.Count }
    severity    = $severityCounts
    bands       = $bands
    domains     = $domains
    paths       = $paths
    frameworks  = $frameworks
    licences    = $licences
    changes     = $changes
    admins      = $admins
    ca          = $caScenarios
    notRun      = $notRunGroups
    summary     = (Hide-Email $summaryText)
    topRisks    = @($topRisks | ForEach-Object id)
    model       = [ordered]@{ severityWeight = $model.SeverityWeight; areaMultiplier = $model.AreaMultiplier; quickWin = $model.QuickWin; roadmap = $model.Roadmap }
    findings    = @($rows | Sort-Object @{ Expression = { $_.result -eq 'Failed' }; Descending = $true }, @{ Expression = 'priority'; Descending = $true })
}

$json = $data | ConvertTo-Json -Depth 12 -Compress
$json = $json.Replace('</', '<\/').Replace([string][char]0x2028, ' ').Replace([string][char]0x2029, ' ')
$template = Get-Content -LiteralPath $templatePath -Raw
$html = $template.Replace('/*__DATA__*/null', $json)
Set-Content -LiteralPath $OutputPath -Value $html -Encoding utf8

# Action list for the client's ticketing: ranked failures with blank owner, due date and status columns.
$csvPath = Join-Path (Split-Path (Resolve-Path -LiteralPath $OutputPath).Path -Parent) 'findings-action-list.csv'
$rank = 0
$data.findings | Where-Object { $_.result -eq 'Failed' -and $_.severity -ne 'Info' } | ForEach-Object {
    $rank++
    $f = $_
    [pscustomobject][ordered]@{
        Rank = $rank; Band = $(switch ($f.band) { 'now' { 'Now (0-30 days)' } 'next' { 'Next (30-90 days)' } default { 'Later' } })
        Id = $f.id; Title = $f.title; Severity = $f.severity; Area = $f.areaName; Product = $f.domain
        AttackPath = (($model.AttackPaths | Where-Object { $_.id -eq $f.path }).name); Risk = $f.risk; Effort = $f.effort
        QuickWin = $(if ($f.quick) { 'Yes' } else { '' }); CisLevel = $(if ($f.cis) { $f.cis.level } else { '' })
        Owner = ''; DueDate = ''; Status = ''; Notes = ''
    }
} | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding utf8

$size = [math]::Round((Get-Item -LiteralPath $OutputPath).Length / 1MB, 2)
Write-Host "Wrote $OutputPath ($size MB) and $csvPath. Score $overallScore, coverage $coverage%, $($failedReal.Count) failed; roadmap now $($bands.now), next $($bands.next), later $($bands.later)." -ForegroundColor Green
if ($changes) { Write-Host "Compared with the run of $($changes.previousAt): $($changes.fixed.Count) fixed, $($changes.regressed.Count) newly failing, $($changes.newChecks.Count) new checks." -ForegroundColor Green }
