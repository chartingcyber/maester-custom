#Requires -Version 7.4
<#
.SYNOPSIS
Runs the whole Resourcive assessment in one command, in place of Connect-Maester, Install-MtPack and Invoke-Maester.

.DESCRIPTION
1. Loads the cloned Maester module (never a gallery copy).
2. Signs in to Microsoft Graph once with Maester's scopes plus the pack's (Uses.GraphScopes in maester-pack.json),
   so the administrator approves everything in a single consent prompt, then verifies the scopes were granted.
3. Connects Exchange Online, Security & Compliance and Teams through Connect-Maester.
4. Installs the pack (you review and approve it) and runs Invoke-Maester for the built-in tests and the pack.
5. Builds the findings report (New-ResourciveReport.ps1) from the results, unless -NoReport is set.
Nothing in the tenant is changed. Run it in a fresh pwsh window, before anything has connected to Exchange,
Teams or Azure.

.PARAMETER TenantId
The tenant's domain or ID. Required, so consent lands in the right tenant.

.PARAMETER GraphOnly
Sign in to Graph only, verify scopes and stop. For the administrator who just approves consent.

.PARAMETER ConnectOnly
Connect (steps 1 to 3) and stop, leaving the session connected for your own Invoke-Maester.

.PARAMETER Service
Services to connect after Graph. Default: ExchangeOnline, SecurityCompliance, Teams.

.PARAMETER ExpectedCountries
Two-letter ISO 3166-1 country codes where sign-ins are expected, for example GB, IE. Default: US, CA. The sign-in country check (3005) fails on any successful sign-in from another country. Codes: https://www.iso.org/obp/ui/#search/code/

.PARAMETER OutputFolder
Where results go. Default: ./test-results/<TenantId>_<yyyyMMdd-HHmmss>, stamped with the local time the script started, so every run (including repeat runs against the same tenant) gets its own folder.

.PARAMETER NoReport
Do not build the findings report (findings-report.html and findings-action-list.csv) after the run.

.PARAMETER MaskNames
Mask email addresses in the findings report, keeping the first three characters of each. Use it for a copy that leaves the team.

.PARAMETER SkipLongRunning
Leave out the long-running checks: Maester's own, and the pack's (found from the LongRunning flag in each check). Naming a pack would otherwise run its long-running checks.

.PARAMETER AllowPartial
When the account cannot get admin approval (a Global Reader), connect with Maester's own scopes only and run, so the pack's checks that need extra scopes skip as "Not authorized". Without it the script requests approval and stops.

.PARAMETER Force
Run even when Graph scopes are missing. Checks that need them are skipped as "Not authorized".

.PARAMETER UseDeviceCode
Use the device code flow for Graph.

.PARAMETER PackPath
The pack folder. Default: ./resourcive-pack beside this script.

.PARAMETER ListScopes
Print the combined scope list and stop, without signing in.

.EXAMPLE
./Invoke-ResourciveAssessment.ps1 -TenantId contoso.com

.EXAMPLE
./Invoke-ResourciveAssessment.ps1 -TenantId contoso.com -GraphOnly
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $TenantId,
    [string[]] $Service = @('ExchangeOnline', 'SecurityCompliance', 'Teams'),
    [switch] $GraphOnly,
    [switch] $ConnectOnly,
    [string] $OutputFolder,
    [switch] $SkipLongRunning,
    [switch] $NoReport,
    [switch] $MaskNames,
    [switch] $Force,
    [switch] $AllowPartial,
    [ValidatePattern('^[A-Za-z]{2}$')] [string[]] $ExpectedCountries,
    [switch] $UseDeviceCode,
    [string] $PackPath = (Join-Path $PSScriptRoot 'resourcive-pack'),
    [switch] $ListScopes
)

$ErrorActionPreference = 'Stop'

# Every run gets its own results folder, named for the tenant and the time the script started, so runs against the
# same tenant over time never overwrite each other.
if (-not $OutputFolder) {
    $OutputFolder = "./test-results/$($TenantId -replace '[^\w.\-]', '_')_$((Get-Date).ToString('yyyyMMdd-HHmmss'))"
}

# 1. Pack scopes from the manifest (the single source of truth).
$manifestPath = Join-Path $PackPath 'maester-pack.json'
if (-not (Test-Path -LiteralPath $manifestPath)) { throw "No maester-pack.json in '$PackPath'." }
$packScopes = @((Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json).Uses.GraphScopes)
if ($packScopes.Count -eq 0) { throw "The manifest in '$PackPath' declares no Uses.GraphScopes." }

# 2. Maester's scopes, from the cloned module. A gallery copy of Maester can be auto-loaded and has an older,
#    shorter scope list and no pack support, so load the clone unless it is already the one in use.
$psd1 = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot 'powershell/Maester.psd1') -ErrorAction SilentlyContinue)?.Path
if (-not $psd1) { throw 'The cloned module powershell/Maester.psd1 was not found. Run this script from the cloned repository.' }
$loaded = Get-Module Maester
if (-not $loaded -or -not $loaded.Path.StartsWith((Split-Path $psd1 -Parent))) {
    Import-Module $psd1 -Force -Global
}
$maesterScopes = @(Get-MtGraphScope)
$required = @($maesterScopes + $packScopes | Sort-Object -Unique)

if ($ListScopes) {
    Write-Host "Maester: $($maesterScopes.Count); pack adds: $(@($packScopes | Where-Object { $_ -notin $maesterScopes }).Count); total: $($required.Count)"
    return $required
}

if ((Get-Module ExchangeOnlineManagement, MicrosoftTeams) -and -not (Get-MgContext)) {
    Write-Warning 'Exchange or Teams is already loaded in this window. Graph sign-in may fail with "Method not found". If it does, open a fresh pwsh and rerun.'
}

# 3. One Graph sign-in for every scope. An administrator sees the usual consent prompt (tick "Consent on behalf of
#    your organization"). A Global Reader cannot grant admin-only scopes: Entra shows "Need admin approval" and,
#    when the tenant has the admin consent workflow on, offers to send a request. Connect-MgGraph then throws; it
#    never connects with a subset.
$graphClientId = '14d82eec-204b-4c2b-b7e8-296a70dab67e'   # Microsoft Graph Command Line Tools
$connect = @{ TenantId = $TenantId; NoWelcome = $true }
if ($UseDeviceCode) { $connect['UseDeviceCode'] = $true }
$status = 'Connected'
$connectedScopes = $required

Write-Host "Signing in to Microsoft Graph for $TenantId with $($required.Count) read-only scopes..." -ForegroundColor Cyan
try {
    Connect-MgGraph @connect -Scopes $required
} catch {
    if ($_.Exception.Message -notmatch 'AADSTS(65001|90094|90095|65002|900941)|consent|admin approval|approval') { throw }
    $status = 'ConsentRequired'
    $scopeUrl = ($required | ForEach-Object { [uri]::EscapeDataString("https://graph.microsoft.com/$_") }) -join '%20'
    $link = "https://login.microsoftonline.com/$TenantId/v2.0/adminconsent?client_id=$graphClientId&scope=$scopeUrl&redirect_uri=http%3A%2F%2Flocalhost"
    Write-Warning 'These Graph permissions need administrator approval, which this account cannot give.'
    Write-Host @"

  1. If Entra offered to request approval, submit it. A Global Administrator approves it under Entra admin center >
     Enterprise apps > Activity > Admin consent requests, for 'Microsoft Graph Command Line Tools'.
  2. If there was no request option, the administrator can either run this same command themselves (tick
     'Consent on behalf of your organization'), or open this link (untested; if it fails, use the command):

     $link

  3. Once approved, run this command again. Nothing else changes.

"@ -ForegroundColor Yellow
    if ($AllowPartial) {
        Write-Host "-AllowPartial: connecting with Maester's own $($maesterScopes.Count) scopes only. Checks that need the pack's extra scopes will skip as 'Not authorized'." -ForegroundColor Yellow
        Connect-MgGraph @connect -Scopes $maesterScopes
        $connectedScopes = $maesterScopes
        $status = 'Partial'
    }
}

$context = if ($status -eq 'ConsentRequired') { $null } else { Get-MgContext }
$granted = @($context.Scopes)
$missing = if ($context) { @($connectedScopes | Where-Object { $_ -notin $granted }) } else { @($required) }

$result = [pscustomobject][ordered]@{
    Status         = $status
    TenantId       = $context.TenantId
    Account        = $context.Account
    RequestedCount = $required.Count
    GrantedCount   = $required.Count - @($required | Where-Object { $_ -in $missing -or $_ -notin $connectedScopes }).Count
    MissingScopes  = @($required | Where-Object { $_ -in $missing -or $_ -notin $connectedScopes })
    OtherServices  = @()
}

if ($status -eq 'ConsentRequired') { return $result }
if ($result.MissingScopes.Count -eq 0) {
    Write-Host "All $($required.Count) Graph scopes granted." -ForegroundColor Green
} elseif ($status -eq 'Connected') {
    Write-Warning "$($result.MissingScopes.Count) scope(s) were not granted: $($result.MissingScopes -join ', ')"
}

# 5. The other services.
if (-not $GraphOnly -and $Service.Count -gt 0) {
    Write-Host "Connecting: $($Service -join ', ')" -ForegroundColor Cyan
    Connect-Maester -Service $Service -TenantId $TenantId
    $result.OtherServices = $Service
    Write-Host "Exchange checks use Exchange roles, not Graph scopes: View-Only Configuration and View-Only Recipients (Global Reader covers them)."
}

if ($GraphOnly -or $ConnectOnly) { return $result }

if ($result.MissingScopes.Count -gt 0 -and $status -eq 'Connected' -and -not $Force) {
    Write-Warning 'Not running: Graph scopes are missing. Get them approved and rerun, or add -Force to run anyway.'
    return $result
}

# 6. Install the pack (interactive approval) and run.
Write-Host 'Installing the pack. Read what it reaches and approve it.' -ForegroundColor Cyan
Install-MtPack $PackPath
$run = @{
    Pack                  = 'RESOURCIVE'
    OutputFolder          = $OutputFolder
    OutputFolderFileName  = 'assessment'
    ExportCsv             = $true
}
if ($ExpectedCountries) {
    # Per-run test parameters go in as a config object merged over the repository config, which is listed first
    # because naming a config here stops Maester reading the config files next to the tests.
    $base = Join-Path $PSScriptRoot 'tests/maester-config.json'
    $override = @{ TestSettings = @(@{ Id = 'MP.RESOURCIVE.3005'; Parameters = @{ ExpectedCountries = @($ExpectedCountries | ForEach-Object { $_.ToUpperInvariant() }) } }) }
    $run['Config'] = @(@(if (Test-Path -LiteralPath $base) { $base }) + $override)
    Write-Host "Expected sign-in countries: $((@($ExpectedCountries | ForEach-Object { $_.ToUpperInvariant() })) -join ', ')" -ForegroundColor Yellow
}
if ($SkipLongRunning) {
    # Naming a pack lifts the long-running exclusion for that pack, so -IncludeLongRunning being absent is not
    # enough: exclude the pack's own long-running checks by ID. They are found from the LongRunning flag in each
    # check's [MaesterTest()] attribute, so a check tagged later is skipped without changing this script.
    $skipIds = foreach ($file in (Get-ChildItem -LiteralPath $PackPath -Recurse -Filter 'Test.*.ps1' -File)) {
        $attribute = [regex]::Match((Get-Content -LiteralPath $file.FullName -Raw), '(?ms)\[MaesterTest\((.*?)\)\]')
        if ($attribute.Success -and $attribute.Groups[1].Value -match '(?m)^\s*LongRunning\s*(,|$)') {
            $id = [regex]::Match($attribute.Groups[1].Value, "(?m)^\s*Id\s*=\s*'([^']+)'")
            if ($id.Success) { $id.Groups[1].Value; "$($id.Groups[1].Value).*" }
        }
    }
    if ($skipIds) {
        $run['ExcludeTestId'] = @($skipIds)
        Write-Host "Skipping the pack's long-running checks: $((@($skipIds | Where-Object { $_ -notmatch '\.\*$' }) -join ', '))" -ForegroundColor Yellow
    }
} else {
    $run['IncludeLongRunning'] = $true
}
Write-Host "Running Maester. A full run can take 25 minutes or more; results go to $OutputFolder" -ForegroundColor Cyan
Invoke-Maester @run

# 7. The findings report. A failure here must not lose the run: the results are already on disk.
$reportPath = $null
if (-not $NoReport) {
    try {
        Write-Host 'Building the findings report...' -ForegroundColor Cyan
        $report = @{ ResultPath = $OutputFolder }
        if ($MaskNames) { $report['MaskNames'] = $true }
        & (Join-Path $PSScriptRoot 'New-ResourciveReport.ps1') @report
        $reportPath = Join-Path $OutputFolder 'findings-report.html'
    } catch {
        Write-Warning "The findings report could not be built: $($_.Exception.Message). The results are in $OutputFolder; run ./New-ResourciveReport.ps1 -ResultPath $OutputFolder to try again."
    }
}
if ($reportPath) {
    Write-Host "Done. Open $reportPath (the findings report) or $OutputFolder/assessment.html (every check)." -ForegroundColor Green
} else {
    Write-Host "Done. Open $OutputFolder/assessment.html" -ForegroundColor Green
}
$result
