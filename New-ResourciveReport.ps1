#Requires -Version 7.4
<#
.SYNOPSIS
Builds a single-file HTML findings report from a Maester result, ordered by risk.

.DESCRIPTION
Reads assessment.json (from Invoke-Maester or Invoke-ResourciveAssessment.ps1) and writes one self-contained HTML
file that works offline. Findings are ranked by risk and effort using resourcive-report/risk-model.json, which you
can edit. The report shows a score, the quick wins, every finding by area, and what could not be assessed and why.

Nothing is sent anywhere. Email addresses are shown in full, because an administrator inventory is only useful when
you can tell who the accounts are. Use -MaskNames before sharing the file outside the people who run the tenant: it
keeps the first three characters of each address (joh***@contoso.com). Device names and IP addresses are not masked.

How the numbers are made:
 - Each failed check has a risk: severity weight x area multiplier (risk-model.json).
 - Effort is the check's implementation cost plus its user impact. Priority is risk divided by effort.
 - Quick wins are high-risk, low-effort failures.
 - The score is the weighted share of assessed checks that passed. Checks that were skipped, errored or need a
   person to review are left out of the score and listed under "Not assessed", never counted as passed.
 - A check that expands into many scenarios (such as the Conditional Access What-If scenarios) is one finding, with
   the scenario counts shown.

.PARAMETER ResultPath
A results folder or an assessment.json file.

.PARAMETER OutputPath
Where to write the HTML. Default: findings-report.html beside the result.

.PARAMETER Title
Report title. Default: the tenant name from the result.

.PARAMETER SummaryPath
Optional text or markdown file whose content replaces the generated summary on the first page. Use it for your own
analysis of the tenant.

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
    [switch] $MaskNames
)

$ErrorActionPreference = 'Stop'

$jsonPath = if (Test-Path -LiteralPath $ResultPath -PathType Container) { Join-Path $ResultPath 'assessment.json' } else { $ResultPath }
if (-not (Test-Path -LiteralPath $jsonPath)) { throw "No assessment.json found at '$ResultPath'." }
if (-not $OutputPath) { $OutputPath = Join-Path (Split-Path (Resolve-Path -LiteralPath $jsonPath).Path -Parent) 'findings-report.html' }

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

function First($value) { @($value | Where-Object { $_ })[0] }

$tests = @($result.Tests)

# Classify skips and the rows that never ran.
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

# One finding per test; scenario families (tests with a ParentId) become one finding.
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

$rows = foreach ($item in $findings) {
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
    $source = [string]$t.Source
    $kind = if ($outcome -in 'Passed', 'Failed') { '' } else { Get-NotAssessedKind $t }
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
        mitre    = @($t.Mitre | Where-Object { $_ -and $_ -ne 'None' })
        controls = @($t.Control | Where-Object { $_ -and $_ -ne 'None' })
        source   = $source
        suite    = [string]$t.Suite
        kind     = $kind
        reason   = Hide-Email ([string]$t.ReasonDetail)
        desc     = Hide-Email (Limit ([string]$t.ResultDetail.TestDescription) 1800)
        detail   = Hide-Email (Limit $detail 3500)
        family   = $item.Family
        helpUrl  = [string]$t.HelpUrl
    }
}
$rows = @($rows)

# Rows that never ran (opt-in services, previews), counted only.
$notRun = @($tests | Where-Object Result -eq 'NotRun')
$notRunGroups = @($notRun | Group-Object { if ($_.ReasonCode -eq 'OptInServiceNotConnected') { "Optional service not connected: $($_.Product)" } else { "$($_.ReasonCode)" } } | Sort-Object Count -Descending | ForEach-Object { [pscustomobject]@{ label = $_.Name; count = $_.Count } })

# Quick wins: failed, high risk, low effort. Info findings never count as risk.
$quick = $model.QuickWin
foreach ($r in $rows) {
    $r | Add-Member -NotePropertyName quick -NotePropertyValue ($r.result -eq 'Failed' -and $r.risk -ge $quick.MinRisk -and $r.effort -le $quick.MaxEffort) -Force
}

# Score.
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

# Generated summary (replaced by -SummaryPath when given).
$weakest = @($domains | Where-Object { $null -ne $_.score } | Select-Object -First 2)
$generated = @()
$generated += "$($failedReal.Count) of $($assessed.Count) assessed checks failed. $($severityCounts.Critical) are Critical and $($severityCounts.High) are High."
if ($weakest.Count -gt 0) { $generated += "The lowest-scoring areas are $(($weakest | ForEach-Object { "$($_.name) ($($_.score))" }) -join ' and ')." }
if ($quickWins.Count -gt 0) { $generated += "$($quickWins.Count) failing checks are quick wins: high risk, little effort and little user impact." }
if ($coverage -ne $null -and $coverage -lt 100) { $generated += "Coverage is $coverage%: $($inScopeNotAssessed.Count) in-scope checks could not be assessed, listed on the Not assessed tab. They are not counted as passed." }
$summaryText = if ($SummaryPath) { Get-Content -LiteralPath $SummaryPath -Raw } else { $generated -join "`n`n" }

# Admin inventory: from check 3010 when the run has it, otherwise from the privileged-user table of 3002.
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
        tables  = @($parsed | ForEach-Object {
                if ($adminId -eq 'MP.RESOURCIVE.3002' -and -not $_.title) { $_.title = 'Accounts' }
                $_
            })
    }
    break
}

$data = [ordered]@{
    meta     = [ordered]@{
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
    score    = $overallScore
    coverage = $coverage
    counts   = [ordered]@{ passed = $assessed.Count - $failedReal.Count; failed = $failedReal.Count; investigate = @($rows | Where-Object result -eq 'Investigate').Count; skipped = @($rows | Where-Object result -eq 'Skipped').Count; errors = @($rows | Where-Object result -eq 'Error').Count; notRun = $notRun.Count }
    severity = $severityCounts
    domains  = $domains
    notRun   = $notRunGroups
    summary  = (Hide-Email $summaryText)
    admins   = $admins
    topRisks = @($topRisks | ForEach-Object id)
    model    = [ordered]@{ severityWeight = $model.SeverityWeight; areaMultiplier = $model.AreaMultiplier; quickWin = $model.QuickWin }
    findings = @($rows | Sort-Object @{ Expression = { $_.result -eq 'Failed' }; Descending = $true }, @{ Expression = 'priority'; Descending = $true })
}

$json = $data | ConvertTo-Json -Depth 12 -Compress
$json = $json.Replace('</', '<\/').Replace([string][char]0x2028, ' ').Replace([string][char]0x2029, ' ')
$template = Get-Content -LiteralPath $templatePath -Raw
$html = $template.Replace('/*__DATA__*/null', $json)
Set-Content -LiteralPath $OutputPath -Value $html -Encoding utf8

$size = [math]::Round((Get-Item -LiteralPath $OutputPath).Length / 1MB, 2)
Write-Host "Wrote $OutputPath ($size MB). Score $overallScore, coverage $coverage%, $($failedReal.Count) failed, $($quickWins.Count) quick wins." -ForegroundColor Green
