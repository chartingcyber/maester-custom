function Get-ResCaInstance {
    <#
    .SYNOPSIS
    Returns one instance per Conditional Access What If scenario of the tenant.

    .DESCRIPTION
    Instance source of the MP.RESOURCIVE.CA family. It discovers real users as personas (one per group of users
    that the policies treat alike, plus every privileged user), derives the sign-in conditions from what the
    policies reference, builds the scenarios one factor at a time from a baseline, keeps them up to the cap
    round-robin by persona (every persona gets a legacy probe, a modern baseline, a platform and a location
    variation before any gets more), and gives each an expectation and a severity. The What If calls happen in the test, not here.

    An instance source takes no parameters, so its knobs are Maester settings (GlobalSettings in the run config):
    Resourcive.CA.MaxScenarios (300), Resourcive.CA.MaxPrivilegedUsers (25), Resourcive.CA.IncludeReportOnly
    (true), Resourcive.CA.MaxUsers (5000), Resourcive.CA.MaxExplicitApps (8), Resourcive.CA.MaxLocations (4),
    Resourcive.CA.PersonaFile (empty), Resourcive.CA.RefreshPersonas (false), Resourcive.CA.DesiredStateFile
    (empty) and Resourcive.CA.RedactUserNames (false).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    Assert-ResLicense -Name 'Microsoft Entra ID P1' -ServicePlan @('AAD_PREMIUM', 'AAD_PREMIUM_P2')

    $maxScenarios = [int](Get-MtSetting -Name 'Resourcive.CA.MaxScenarios' -Default 300)
    $maxPrivileged = [int](Get-MtSetting -Name 'Resourcive.CA.MaxPrivilegedUsers' -Default 25)
    $includeReportOnly = [bool](Get-MtSetting -Name 'Resourcive.CA.IncludeReportOnly' -Default $true)
    $maxUsers = [int](Get-MtSetting -Name 'Resourcive.CA.MaxUsers' -Default 5000)
    $maxApps = [int](Get-MtSetting -Name 'Resourcive.CA.MaxExplicitApps' -Default 8)
    $maxLocations = [int](Get-MtSetting -Name 'Resourcive.CA.MaxLocations' -Default 4)
    $personaFile = [string](Get-MtSetting -Name 'Resourcive.CA.PersonaFile' -Default '')
    $refresh = [bool](Get-MtSetting -Name 'Resourcive.CA.RefreshPersonas' -Default $false)
    $desiredFile = [string](Get-MtSetting -Name 'Resourcive.CA.DesiredStateFile' -Default '')
    $redact = [bool](Get-MtSetting -Name 'Resourcive.CA.RedactUserNames' -Default $false)

    $desired = Read-ResCaDesiredState -Path $desiredFile

    try {
        $set = Get-ResCaPersonaSet -MaxPrivilegedUsers $maxPrivileged -IncludeReportOnly $includeReportOnly -MaxUsers $maxUsers -PersonaFile $personaFile -RefreshPersonas $refresh
    } catch {
        Resolve-ResGraphError -ErrorRecord $_ -Feature 'Conditional Access policies, users and role assignments' -Requires 'Policy.Read.All, User.Read.All, RoleManagement.Read.Directory, GroupMember.Read.All (Global Reader covers these)'
    }

    if (@($set.Policies).Count -eq 0) {
        Add-MtTestResultDetail -SkippedBecause NotApplicable
    }

    $axis = Get-ResCaAxis -Policy $set.Policies -NamedLocation $set.NamedLocations -P2Licensed $set.P2Licensed -MaxExplicitApps $maxApps -MaxLocations $maxLocations
    $cache = [hashtable]::Synchronized(@{})
    foreach ($app in @($axis.Apps | Where-Object { $_.Group -eq 'Other' })) {
        $resolved = (Resolve-ResCaAppName -AppId @($app.Id) -Cache $cache)[[string]$app.Id]
        if ($resolved -and $resolved -ne $app.Id) { $app.Name = $resolved }
    }
    $all = @(New-ResCaScenario -Persona $set.Personas -Axis $axis)
    $kept = @(Select-ResCaScenario -Scenario $all -MaxScenarios $maxScenarios)

    $notes = @($set.Notes) + @($axis.Notes)
    $lostByPersona = @{}
    if ($kept.Count -gt 0 -and $kept[0].Truncated -gt 0) {
        $lost = @(Get-ResCaTruncationNote -All $all -Kept $kept)
        foreach ($l in $lost) { $lostByPersona[$l.PersonaKey] = $l.Text }
        $notes += "The scenario cap cut $($kept[0].Truncated) of $($all.Count) scenarios (Resourcive.CA.MaxScenarios = $maxScenarios). The cap is applied round-robin by persona: each persona gets its legacy probe, a modern baseline, a platform and a location variation before any persona gets a second of anything, privileged personas first. Raise Resourcive.CA.MaxScenarios to probe the rest."
        $notes += "Personas that lost scenarios, and which axes ($($lost.Count) of $(@($set.Personas).Count) personas): $((@($lost | Select-Object -First 25) | ForEach-Object { $_.Text }) -join ' | ')$(if ($lost.Count -gt 25) { " | and $($lost.Count - 25) more" })"
    }
    $notes += 'What If runs against the policies as they are now. Every scenario sets client app type, platform, country and risk explicitly, because What If does not evaluate a condition it is not given.'

    $asOf = [datetime]::UtcNow
    $deviceOk = [bool]($desired -and $desired.DeviceRequiredSatisfiesMfa)

    foreach ($s in $kept) {
        $expectation = Get-ResCaExpectation -Scenario $s -Desired $desired
        $target = if ($s.UserAction) { "user action $($s.UserAction)" } else { $s.App.Name }
        $who = if ($redact) { $s.Persona.Label } else { "$($s.Persona.Label) $($s.Persona.UserPrincipalName)" }
        $id = $s.Key -replace '[^A-Za-z0-9._-]', '-'
        if ($id.Length -gt 120) {
            $hash = [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($s.Key))).Replace('-', '').Substring(0, 12).ToLowerInvariant()
            $id = '{0}-{1}' -f $id.Substring(0, 100), $hash
        }
        [pscustomobject]@{
            Id       = $id
            Title    = "$who signs in to $target from $($s.LocationKey) with $($s.ClientAppType) on $($s.DevicePlatform)$(if ($s.SignInRiskLevel -ne 'None') { ", sign-in risk $($s.SignInRiskLevel)" })$(if ($s.UserRiskLevel -ne 'None') { ", user risk $($s.UserRiskLevel)" })."
            Severity = $expectation.Severity
            Data     = @{
                Scenario                   = $s
                Expectation                = $expectation
                Cache                      = $cache
                Note                       = @($notes) + @(if ($lostByPersona.ContainsKey($s.PersonaKey)) { "This row's persona: $($lostByPersona[$s.PersonaKey])." } elseif ($kept[0].Truncated -gt 0) { "This row's persona lost no scenarios to the cap." })
                Policies                   = $set.Policies
                AsOf                       = $asOf
                Redact                     = $redact
                DeviceRequiredSatisfiesMfa = $deviceOk
            }
        }
    }
}

function Test-ResCaScenario {
    <#
    .SYNOPSIS
    Checks that Conditional Access gives the expected outcome for one sign-in scenario.

    .DESCRIPTION
    Runs once per scenario from the instance source. It asks the Conditional Access What If API what would happen
    when a real user of the tenant signs in with the scenario's application, client, platform, location and risk,
    classifies the result from the enforced policies that apply (Block, PhishingResistant, MFA, DeviceRequired,
    AppRequired, NoControl or NotAssessed), and compares it with the expectation. Report-only policies are shown but never
    count towards a pass, and a scenario What If cannot evaluate is Investigate, never a pass.

    The test skips with a reason starting "Not licensed:" when the tenant has no Entra ID P1, and with a reason
    starting "Not authorized:" when Graph refuses the call.

    .LINK
    https://learn.microsoft.com/entra/identity/conditional-access/what-if-tool
    #>
    [MaesterTest(
        Id = 'MP.RESOURCIVE.CA',
        Title = 'Conditional Access gives the expected outcome for a sign-in scenario.',
        Product = 'entra',
        Feature = 'conditional-access',
        Area = 'access-control',
        ResourceType = 'User',
        Severity = 'High',
        UserImpact = 'Medium',
        ImplementationCost = 'Medium',
        Mitre = ('T1078.004', 'T1110.003'),
        Control = ('nist-800-53-r5:IA-2(1)', 'nist-800-53-r5:IA-2(2)'),
        Service = 'Graph',
        License = 'AAD_PREMIUM',
        InstanceSource = 'Get-ResCaInstance',
        LongRunning,
        Author = 'resourcive'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        # The scenario to evaluate, supplied by the engine.
        $Instance,

        # Wait this long before each What If call, in milliseconds, to stay under the throttling limits.
        [ValidateRange(0, 60000)]
        [int] $ThrottleMilliseconds = 250
    )

    Assert-ResLicense -Name 'Microsoft Entra ID P1' -ServicePlan @('AAD_PREMIUM', 'AAD_PREMIUM_P2')

    $data = $Instance.Data
    $scenario = $data.Scenario
    try {
        $rows = Invoke-ResCaWhatIf -Scenario $scenario -Cache $data.Cache -ThrottleMilliseconds $ThrottleMilliseconds
    } catch {
        Resolve-ResGraphError -ErrorRecord $_ -Feature 'the Conditional Access What If evaluation' -Requires 'Policy.Read.ConditionalAccess or Policy.Read.All'
    }

    $outcome = Get-ResCaOutcome -Result $rows -Policy @($data.Policies)
    $verdict = Test-ResCaExpectation -Outcome $outcome -Expectation $data.Expectation -DeviceRequiredSatisfiesMfa:$data.DeviceRequiredSatisfiesMfa -ClientAppType $scenario.ClientAppType
    $text = Format-ResCaResult -Scenario $scenario -Outcome $outcome -Expectation $data.Expectation -Verdict $verdict -Note @($data.Note) -AsOf $data.AsOf -Redact:$data.Redact -Cache $data.Cache

    switch ($verdict.Status) {
        'Pass' {
            Add-MtTestResultDetail -Result $text
            return $true
        }
        'Fail' {
            Add-MtTestResultDetail -Result $text
            return $false
        }
        default {
            Add-MtTestResultDetail -Result $text -Investigate
            return $true
        }
    }
}
