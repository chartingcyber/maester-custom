# Smoke test of the family's instance source and test function with every Graph call stubbed.
# It loads the Maester module only for the [MaesterTest] attribute type.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../powershell/Maester.psd1') -Force -ErrorAction Stop
    foreach ($file in (Get-ChildItem -Path (Join-Path $PSScriptRoot '../../resourcive-pack/helpers') -Filter '*.ps1' | Where-Object { $_.Name -match '-ResCa|^(Assert-ResLicense|Test-ResLicense|Get-ResLicensedServicePlan|Resolve-ResGraphError|Get-ResPrivilegedUser)\.ps1$' })) { . $file.FullName }
    . (Join-Path $PSScriptRoot '../../resourcive-pack/conditional-access/Test.MP.RESOURCIVE.CA.ps1')

    function New-Result {
        param($Id, $State = 'enabled', $Applies = $true, $Reason = 'notSet', $Controls = @(), $Name = $Id)
        [pscustomobject]@{ id = $Id; displayName = $Name; state = $State; policyApplies = $Applies; analysisReasons = $Reason; grantControls = [pscustomobject]@{ operator = 'OR'; builtInControls = $Controls; authenticationStrength = $null } }
    }
}

Describe 'MP.RESOURCIVE.CA family' {
    BeforeEach {
        Mock Assert-ResLicense { }
        Mock Get-MtSetting { param($Name, $Default) $Default }
        Mock Get-MtConditionalAccessPolicy {
            @([pscustomobject]@{ id = 'p1'; displayName = 'MFA all'; state = 'enabled'; grantControls = $null
                    conditions = [pscustomobject]@{ users = [pscustomobject]@{ includeUsers = @('All'); excludeUsers = @(); includeGroups = @(); excludeGroups = @(); includeRoles = @(); excludeRoles = @() }
                        applications = [pscustomobject]@{ includeApplications = @('All'); excludeApplications = @(); includeUserActions = @() }; platforms = $null } })
        }
        Mock Test-ResLicense { $false }
        Mock Get-ResPrivilegedUser { [pscustomobject]@{ Id = '00000000-0000-0000-0000-0000000000a1'; UserPrincipalName = 'admin@contoso.com'; DisplayName = 'Admin'; Roles = @('Global Administrator'); EligibleReadable = $true } }
        Mock Get-ResCaUserRoleMap { @{} }
        Mock Invoke-MtGraphRequest {
            if ($RelativeUri -eq 'users') { @([pscustomobject]@{ id = '00000000-0000-0000-0000-0000000000b1'; userPrincipalName = 'u1@contoso.com'; displayName = 'U1'; userType = 'Member' }) }
            else { @() }
        }
        Mock Start-Sleep { }
    }
    It 'produces valid, unique instances with a severity, and records the P2 note and the cap' {
        $instances = @(Get-ResCaInstance)
        $instances.Count | Should -BeGreaterThan 0
        ($instances.Id | Select-Object -Unique).Count | Should -Be $instances.Count
        foreach ($i in $instances) {
            $i.Id | Should -Match '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'
            $i.Severity | Should -BeIn @('Critical', 'High', 'Medium', 'Low', 'Info')
        }
        ($instances[0].Data.Note -join ' ') | Should -Match 'Risk axes omitted: Entra ID P2 not licensed'
        $instances[0].Severity | Should -Be 'Critical'
    }
    It 'skips the family with NotApplicable when there are no enabled policies' {
        Mock Get-MtConditionalAccessPolicy { @() }
        Mock Add-MtTestResultDetail { throw 'skipped' }
        { Get-ResCaInstance } | Should -Throw 'skipped'
        Should -Invoke Add-MtTestResultDetail -ParameterFilter { $SkippedBecause -eq 'NotApplicable' }
    }
    It 'fails a privileged legacy-client scenario that nothing blocks, and passes it when a policy blocks' {
        $instance = @(Get-ResCaInstance) | Where-Object { $_.Data.Scenario.Persona.Kind -eq 'Privileged' -and $_.Data.Scenario.ClientAppType -eq 'exchangeActiveSync' } | Select-Object -First 1
        $instance | Should -Not -BeNullOrEmpty
        Mock Add-MtTestResultDetail { }
        Mock Test-MtConditionalAccessWhatIf { @(New-Result -Id 'p1' -Applies $false -Reason 'users') }
        Test-ResCaScenario -Instance $instance -ThrottleMilliseconds 0 | Should -BeFalse

        $instance.Data.Cache.Clear()
        Mock Test-MtConditionalAccessWhatIf { @(New-Result -Id 'p2' -Controls @('block')) }
        Test-ResCaScenario -Instance $instance -ThrottleMilliseconds 0 | Should -BeTrue
        Should -Invoke Add-MtTestResultDetail -ParameterFilter { $Result -like 'Well done.*' }
    }
    It 'marks a scenario What If could not evaluate as Investigate, not Pass' {
        $instance = @(Get-ResCaInstance) | Select-Object -First 1
        Mock Add-MtTestResultDetail { }
        Mock Test-MtConditionalAccessWhatIf { @(New-Result -Id 'p1' -Applies $false -Reason 'notEnoughInformation' -Controls @('mfa')) }
        Test-ResCaScenario -Instance $instance -ThrottleMilliseconds 0 | Out-Null
        Should -Invoke Add-MtTestResultDetail -ParameterFilter { $Investigate }
    }
    It 'turns a Graph licence error into a Not licensed skip' {
        $instance = @(Get-ResCaInstance) | Select-Object -First 1
        Mock Add-MtTestResultDetail { throw 'skipped' }
        Mock Test-MtConditionalAccessWhatIf { throw 'Neither tenant is B2C or tenant does not have a premium license' }
        { Test-ResCaScenario -Instance $instance -ThrottleMilliseconds 0 } | Should -Throw 'skipped'
        Should -Invoke Add-MtTestResultDetail -ParameterFilter { $SkippedCustomReason -like 'Not licensed:*' }
    }
    It 'passes a legacy client that only gets MFA as a de facto block' {
        $instance = @(Get-ResCaInstance) | Where-Object { $_.Data.Scenario.Persona.Kind -eq 'Privileged' -and $_.Data.Scenario.ClientAppType -eq 'exchangeActiveSync' } | Select-Object -First 1
        Mock Add-MtTestResultDetail { }
        Mock Test-MtConditionalAccessWhatIf { @(New-Result -Id 'p1' -Controls @('mfa')) }
        Test-ResCaScenario -Instance $instance -ThrottleMilliseconds 0 | Should -BeTrue
        Should -Invoke Add-MtTestResultDetail -ParameterFilter { $Result -like 'Well done.*de facto block, an explicit block policy is still recommended*' -and $Result -like '*finding severity Low*' }
    }
    It 'shows Investigate with the reason, never an error, when What If keeps returning HTTP 500' {
        $instance = @(Get-ResCaInstance) | Select-Object -First 1
        Mock Add-MtTestResultDetail { }
        Mock Test-MtConditionalAccessWhatIf { throw 'Response status code does not indicate success: 500 (InternalServerError).' }
        { Test-ResCaScenario -Instance $instance -ThrottleMilliseconds 0 } | Should -Not -Throw
        Should -Invoke Add-MtTestResultDetail -ParameterFilter { $Investigate -and $Result -match 'failed after retries' }
    }
    It 'says per row which axes the cap removed for that persona, and lists personas in the notes' {
        Mock Get-MtSetting { param($Name, $Default) if ($Name -eq 'Resourcive.CA.MaxScenarios') { 3 } else { $Default } }
        $instances = @(Get-ResCaInstance)
        $instances.Count | Should -Be 3
        ($instances[0].Data.Note -join ' ') | Should -Match 'The scenario cap cut'
        ($instances[0].Data.Note -join ' ') | Should -Match "This row's persona:"
        ($instances[0].Data.Note -join ' ') | Should -Match 'Personas that lost scenarios, and which axes'
    }
    It 'records the home location and the platforms in the notes' {
        $note = (@(Get-ResCaInstance)[0].Data.Note -join ' ')
        $note | Should -Match 'Home location: US chosen'
        $note | Should -Match 'Platforms probed: windows, iOS, Android and macOS always'
    }
}
