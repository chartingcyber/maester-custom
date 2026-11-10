# Unit tests for the pure logic of the MP.RESOURCIVE.CA family. No tenant is needed: Graph and Maester commands are stubbed.
# Run: Invoke-Pester ./resourcive-pack/unit-tests/ca

BeforeAll {
    $helpers = Join-Path $PSScriptRoot '../../resourcive-pack/helpers'
    foreach ($file in (Get-ChildItem -Path $helpers -Filter '*.ps1' | Where-Object { $_.Name -match '-ResCa|^(Assert-ResLicense|Test-ResLicense|Get-ResLicensedServicePlan|Resolve-ResGraphError|Get-ResPrivilegedUser)\.ps1$' })) { . $file.FullName }

    # Stubs for commands that the code under test calls and that tests mock.
    function Invoke-MtGraphRequest { param($RelativeUri, $ApiVersion, $Filter, $Select, $QueryParameters, $ErrorAction, [switch]$DisableCache) }
    function Get-MtConditionalAccessPolicy { param([switch]$DisableCache) }
    function Get-MtSetting { param($Name, $Default) }
    function Test-MtConditionalAccessWhatIf { param($UserId, $IncludeApplications, $UserAction, $ClientAppType, $DevicePlatform, $SignInRiskLevel, $UserRiskLevel, $Country, $IpAddress, [switch]$AllResults) }
    function Add-MtTestResultDetail { param($Result, $SkippedBecause, $SkippedCustomReason, [switch]$Investigate) }

    function New-Policy {
        param($Id, $Name = $Id, $State = 'enabled', $Users = @{}, $Grant = $null, $Applies = $true, $Reason = 'notSet')
        [pscustomobject]@{
            id = $Id; displayName = $Name; state = $State; policyApplies = $Applies; analysisReasons = $Reason
            conditions = [pscustomobject]@{ users = [pscustomobject]$Users; applications = [pscustomobject]@{ includeApplications = @('All'); excludeApplications = @(); includeUserActions = @() }; platforms = $null }
            grantControls = $Grant
        }
    }
    function New-Grant { param($Controls = @(), $Operator = 'AND', $Strength = $null) [pscustomobject]@{ operator = $Operator; builtInControls = $Controls; authenticationStrength = $Strength } }
    function New-User { param($Id, $Type = 'Member', $Groups = @(), $Roles = @()) [pscustomobject]@{ Id = $Id; UserPrincipalName = "$Id@contoso.com"; DisplayName = $Id; UserType = $Type; GroupIds = $Groups; RoleIds = $Roles } }
}

Describe 'Get-ResCaIpFromCidr' {
    It 'returns the first host of a range' { Get-ResCaIpFromCidr -Cidr '198.51.100.0/24' | Should -Be '198.51.100.1' }
    It 'returns the address itself for a /32' { Get-ResCaIpFromCidr -Cidr '198.51.100.7/32' | Should -Be '198.51.100.7' }
    It 'returns $null for IPv6 and bad input' {
        Get-ResCaIpFromCidr -Cidr '2001:db8::/32' | Should -BeNullOrEmpty
        Get-ResCaIpFromCidr -Cidr '300.1.1.1/24' | Should -BeNullOrEmpty
        Get-ResCaIpFromCidr -Cidr '' | Should -BeNullOrEmpty
    }
}

Describe 'Get-ResCaPolicyScope and Group-ResCaUserByScope' {
    It 'includes All, excludes by user, group and role' {
        $all = New-Policy -Id 'p1' -Users @{ includeUsers = @('All'); excludeUsers = @('u-excluded'); excludeGroups = @('g-admins'); excludeRoles = @('r-ga') }
        Get-ResCaPolicyScope -User (New-User 'u1') -Policy $all | Should -Be 'Included'
        Get-ResCaPolicyScope -User (New-User 'u-excluded') -Policy $all | Should -Be 'Excluded'
        Get-ResCaPolicyScope -User (New-User 'u2' -Groups @('g-admins')) -Policy $all | Should -Be 'Excluded'
        Get-ResCaPolicyScope -User (New-User 'u3' -Roles @('r-ga')) -Policy $all | Should -Be 'Excluded'
    }
    It 'targets by group, role and guest type' {
        $byGroup = New-Policy -Id 'p2' -Users @{ includeGroups = @('g1') }
        $byRole = New-Policy -Id 'p3' -Users @{ includeRoles = @('r1') }
        $guests = New-Policy -Id 'p4' -Users @{ includeUsers = @('GuestsOrExternalUsers') }
        Get-ResCaPolicyScope -User (New-User 'u1' -Groups @('g1')) -Policy $byGroup | Should -Be 'Included'
        Get-ResCaPolicyScope -User (New-User 'u1') -Policy $byGroup | Should -Be 'None'
        Get-ResCaPolicyScope -User (New-User 'u1' -Roles @('r1')) -Policy $byRole | Should -Be 'Included'
        Get-ResCaPolicyScope -User (New-User 'g1' -Type 'Guest') -Policy $guests | Should -Be 'Included'
        Get-ResCaPolicyScope -User (New-User 'u1') -Policy $guests | Should -Be 'None'
    }
    It 'puts users the policies treat alike in one class and splits by user type' {
        $policies = @(
            (New-Policy -Id 'p1' -Users @{ includeUsers = @('All'); excludeGroups = @('g-exempt') }),
            (New-Policy -Id 'p2' -State 'disabled' -Users @{ includeUsers = @('All') })
        )
        $users = @((New-User 'a'), (New-User 'b'), (New-User 'c' -Groups @('g-exempt')), (New-User 'd' -Type 'Guest'))
        $classes = @(Group-ResCaUserByScope -User $users -Policy $policies)
        $classes.Count | Should -Be 3
        ($classes | Where-Object { $_.UserType -eq 'Member' -and $_.Users.Count -eq 2 }).Users.Id | Should -Contain 'a'
        ($classes | Where-Object { $_.UserType -eq 'Guest' }).Users.Count | Should -Be 1
    }
    It 'ignores disabled policies when classifying' {
        $users = @((New-User 'a'), (New-User 'b' -Groups @('g')))
        $classes = @(Group-ResCaUserByScope -User $users -Policy @((New-Policy -Id 'p1' -State 'disabled' -Users @{ includeGroups = @('g') })))
        $classes.Count | Should -Be 1
    }
}

Describe 'Select-ResCaPersona' {
    BeforeAll {
        $policies = @((New-Policy -Id 'p1' -Users @{ includeUsers = @('All'); excludeGroups = @('g') }))
        $users = @((New-User 'm3'), (New-User 'm1'), (New-User 'm2'), (New-User 'x1' -Groups @('g')), (New-User 'guest1' -Type 'Guest'))
        $classes = @(Group-ResCaUserByScope -User $users -Policy $policies)
        $priv = @(
            [pscustomobject]@{ Id = 'a3'; UserPrincipalName = 'c@contoso.com'; DisplayName = 'C'; Roles = @('Global Administrator') },
            [pscustomobject]@{ Id = 'a1'; UserPrincipalName = 'a@contoso.com'; DisplayName = 'A'; Roles = @('User Administrator', 'Helpdesk Administrator') },
            [pscustomobject]@{ Id = 'a2'; UserPrincipalName = 'b@contoso.com'; DisplayName = 'B'; Roles = @('Security Administrator') }
        )
    }
    It 'tests every privileged user up to the cap, ordered by user principal name' {
        $p = @(Select-ResCaPersona -Class $classes -PrivilegedUser $priv -MaxPrivilegedUsers 2)
        $privileged = @($p | Where-Object { $_.Kind -eq 'Privileged' })
        $privileged.UserPrincipalName | Should -Be @('a@contoso.com', 'b@contoso.com')
        $privileged[0].Label | Should -Be 'Privileged:UserAdministrator'
        $p[0].TruncatedPrivileged | Should -Be 1
    }
    It 'picks one stable representative per class and numbers classes by size' {
        $p = @(Select-ResCaPersona -Class $classes -PrivilegedUser @())
        $members = @($p | Where-Object { $_.Kind -eq 'Member' })
        $members.Count | Should -Be 2
        $members[0].UserPrincipalName | Should -Be 'm1@contoso.com'
        $members[0].ClassSize | Should -Be 3
        $members[0].Key | Should -Be 'member-c01'
        @($p | Where-Object { $_.Kind -eq 'Guest' }).Count | Should -Be 1
    }
    It 'flags emergency access accounts' {
        $p = @(Select-ResCaPersona -Class @() -PrivilegedUser $priv -EmergencyAccess @('B@contoso.com'))
        ($p | Where-Object { $_.UserPrincipalName -eq 'b@contoso.com' }).IsEmergencyAccess | Should -BeTrue
        ($p | Where-Object { $_.UserPrincipalName -eq 'a@contoso.com' }).IsEmergencyAccess | Should -BeFalse
    }
}

Describe 'Get-ResCaGrantFlag' {
    It 'returns nothing for no grant controls' { @(Get-ResCaGrantFlag -GrantControl $null).Count | Should -Be 0 }
    It 'unions flags with AND' {
        $f = Get-ResCaGrantFlag -GrantControl (New-Grant -Controls @('mfa', 'compliantDevice') -Operator 'AND')
        $f | Should -Contain 'MFA'
        $f | Should -Contain 'Device'
    }
    It 'keeps only what every alternative guarantees with OR: the weakest alternative decides' {
        $f = Get-ResCaGrantFlag -GrantControl (New-Grant -Controls @('mfa', 'compliantDevice') -Operator 'OR')
        @($f).Count | Should -Be 0
        $g = Get-ResCaGrantFlag -GrantControl (New-Grant -Controls @('mfa', 'passwordChange') -Operator 'OR')
        $g | Should -Be @('MFA')
    }
    It 'treats the built-in phishing-resistant strength as MFA plus PhishingResistant' {
        $f = Get-ResCaGrantFlag -GrantControl (New-Grant -Strength ([pscustomobject]@{ id = '00000000-0000-0000-0000-000000000004'; displayName = 'Phishing-resistant MFA'; allowedCombinations = @() }))
        $f | Should -Contain 'PhishingResistant'
        $f | Should -Contain 'MFA'
    }
    It 'classifies a custom strength by its combinations' {
        $pr = New-Grant -Strength ([pscustomobject]@{ id = 'x'; displayName = 'Passkeys'; allowedCombinations = @('fido2', 'windowsHelloForBusiness') })
        $weak = New-Grant -Strength ([pscustomobject]@{ id = 'y'; displayName = 'Mixed'; allowedCombinations = @('fido2', 'password,microsoftAuthenticatorPush') })
        Get-ResCaGrantFlag -GrantControl $pr | Should -Contain 'PhishingResistant'
        Get-ResCaGrantFlag -GrantControl $weak | Should -Not -Contain 'PhishingResistant'
        Get-ResCaGrantFlag -GrantControl $weak | Should -Contain 'MFA'
    }
    It 'flags block' { Get-ResCaGrantFlag -GrantControl (New-Grant -Controls @('block')) | Should -Contain 'Block' }
}

Describe 'Get-ResCaOutcome' {
    It 'is NoControl with no applying policy' { (Get-ResCaOutcome -Result @()).Class | Should -Be 'NoControl' }
    It 'ignores policies that do not apply, whatever the reason' {
        $o = Get-ResCaOutcome -Result @(New-Policy -Id 'p1' -Applies $false -Reason 'users' -Grant (New-Grant -Controls @('block')))
        $o.Class | Should -Be 'NoControl'
    }
    It 'adds up the requirements of every applying enforced policy' {
        $o = Get-ResCaOutcome -Result @(
            (New-Policy -Id 'p1' -Grant (New-Grant -Controls @('mfa'))),
            (New-Policy -Id 'p2' -Grant (New-Grant -Controls @('compliantDevice'))))
        $o.Class | Should -Be 'MFA'
        $o.Flags | Should -Contain 'Device'
    }
    It 'is Block when any enforced policy blocks' {
        (Get-ResCaOutcome -Result @((New-Policy -Id 'p1' -Grant (New-Grant -Controls @('mfa'))), (New-Policy -Id 'p2' -Grant (New-Grant -Controls @('block'))))).Class | Should -Be 'Block'
    }
    It 'classifies a device-only requirement as DeviceRequired' {
        (Get-ResCaOutcome -Result @(New-Policy -Id 'p1' -Grant (New-Grant -Controls @('compliantDevice')))).Class | Should -Be 'DeviceRequired'
    }
    It 'keeps report-only policies out of the class and says when coverage depends on them' {
        $o = Get-ResCaOutcome -Result @(New-Policy -Id 'p1' -State 'enabledForReportingButNotEnforced' -Grant (New-Grant -Controls @('mfa')))
        $o.Class | Should -Be 'NoControl'
        $o.ReportOnlyClass | Should -Be 'MFA'
        $o.CoverageDependsOnReportOnly | Should -BeTrue
    }
    It 'ignores disabled policies' {
        (Get-ResCaOutcome -Result @(New-Policy -Id 'p1' -State 'disabled' -Grant (New-Grant -Controls @('block')))).Class | Should -Be 'NoControl'
    }
    It 'is NotAssessed when a policy could not be evaluated' {
        $o = Get-ResCaOutcome -Result @(New-Policy -Id 'p1' -Applies $false -Reason 'notEnoughInformation' -Grant (New-Grant -Controls @('mfa')))
        $o.Class | Should -Be 'NotAssessed'
        @($o.NotAssessedPolicies).Count | Should -Be 1
    }
    It 'lets an enforced block decide even when another policy could not be evaluated' {
        $o = Get-ResCaOutcome -Result @((New-Policy -Id 'p1' -Grant (New-Grant -Controls @('block'))), (New-Policy -Id 'p2' -Applies $false -Reason 'notEnoughInformation'))
        $o.Class | Should -Be 'Block'
    }
}

Describe 'Get-ResCaExpectation and Test-ResCaExpectation' {
    BeforeAll {
        $exo = [pscustomobject]@{ Key = 'exo'; Name = 'Office 365 Exchange Online'; Id = '00000002-0000-0ff1-ce00-000000000000'; Group = 'M365' }
        $arm = [pscustomobject]@{ Key = 'arm'; Name = 'Windows Azure Service Management API'; Id = '797f4846-ba00-4fd7-ba43-dac1f8f63013'; Group = 'Azure' }
        function New-Scenario { param($Kind = 'Member', $App = $exo, $Client = 'browser', $Emergency = $false, $SignIn = 'None', $User = 'None', $Action = $null)
            [pscustomobject]@{ Persona = [pscustomobject]@{ Kind = $Kind; IsEmergencyAccess = $Emergency }; App = $App; ClientAppType = $Client; DevicePlatform = 'windows'; LocationKey = 'home'; UserAction = $Action; Axis = 'baseline'; SignInRiskLevel = $SignIn; UserRiskLevel = $User }
        }
        function New-Outcome { param($Class, $Flags = @(), $ReportOnlyClass = 'NoControl', $Depends = $false, $NotAssessed = @())
            [pscustomobject]@{ Class = $Class; Flags = $Flags; ReportOnlyClass = $ReportOnlyClass; CoverageDependsOnReportOnly = $Depends; NotAssessedPolicies = $NotAssessed } }
    }
    It 'defaults legacy clients to Block, Critical for privileged and High otherwise' {
        (Get-ResCaExpectation -Scenario (New-Scenario -Kind 'Privileged' -Client 'exchangeActiveSync') -Desired $null) | ForEach-Object { $_.Expect | Should -Be 'Block'; $_.Severity | Should -Be 'Critical' }
        (Get-ResCaExpectation -Scenario (New-Scenario -Client 'other') -Desired $null) | ForEach-Object { $_.Severity | Should -Be 'High' }
    }
    It 'defaults privileged to MFA Critical, members on M365 to MFA High, others to Info' {
        (Get-ResCaExpectation -Scenario (New-Scenario -Kind 'Privileged' -App $arm) -Desired $null).Severity | Should -Be 'Critical'
        (Get-ResCaExpectation -Scenario (New-Scenario) -Desired $null).Expect | Should -Be 'MFA'
        (Get-ResCaExpectation -Scenario (New-Scenario -App $arm) -Desired $null).Expect | Should -Be 'Info'
    }
    It 'treats emergency access accounts as informational' {
        (Get-ResCaExpectation -Scenario (New-Scenario -Kind 'Privileged' -Emergency $true) -Desired $null).Expect | Should -Be 'Info'
    }
    It 'uses the first matching desired-state rule' {
        $desired = [pscustomobject]@{ Rules = @(
                [pscustomobject]@{ Persona = 'Member'; App = 'arm'; Expect = 'Block'; Severity = 'Medium' },
                [pscustomobject]@{ Persona = '*'; Expect = 'MFA'; Severity = 'Low' }) }
        $e = Get-ResCaExpectation -Scenario (New-Scenario -App $arm) -Desired $desired
        $e.Expect | Should -Be 'Block'
        $e.Source | Should -Be 'Desired'
        (Get-ResCaExpectation -Scenario (New-Scenario) -Desired $desired).Severity | Should -Be 'Low'
    }
    It 'passes, fails and investigates against an MFA expectation' {
        $mfa = [pscustomobject]@{ Expect = 'MFA'; Severity = 'High' }
        (Test-ResCaExpectation -Outcome (New-Outcome 'MFA') -Expectation $mfa).Status | Should -Be 'Pass'
        (Test-ResCaExpectation -Outcome (New-Outcome 'PhishingResistant') -Expectation $mfa).Status | Should -Be 'Pass'
        (Test-ResCaExpectation -Outcome (New-Outcome 'Block') -Expectation $mfa).Status | Should -Be 'Pass'
        (Test-ResCaExpectation -Outcome (New-Outcome 'NoControl') -Expectation $mfa).Status | Should -Be 'Fail'
        (Test-ResCaExpectation -Outcome (New-Outcome 'DeviceRequired') -Expectation $mfa).Status | Should -Be 'Investigate'
        (Test-ResCaExpectation -Outcome (New-Outcome 'DeviceRequired') -Expectation $mfa -DeviceRequiredSatisfiesMfa).Status | Should -Be 'Pass'
    }
    It 'never passes a NotAssessed outcome and never passes through report-only' {
        $mfa = [pscustomobject]@{ Expect = 'MFA'; Severity = 'High' }
        $na = New-Outcome 'NotAssessed' -NotAssessed @([pscustomobject]@{ displayName = 'P'; analysisReasons = 'notEnoughInformation' })
        (Test-ResCaExpectation -Outcome $na -Expectation $mfa).Status | Should -Be 'Investigate'
        (Test-ResCaExpectation -Outcome (New-Outcome 'NoControl' -ReportOnlyClass 'MFA' -Depends $true) -Expectation $mfa).Status | Should -Be 'Investigate'
    }
    It 'only passes Block when the outcome is Block, and Info is always Investigate' {
        $block = [pscustomobject]@{ Expect = 'Block'; Severity = 'High' }
        (Test-ResCaExpectation -Outcome (New-Outcome 'MFA') -Expectation $block).Status | Should -Be 'Fail'
        (Test-ResCaExpectation -Outcome (New-Outcome 'Block') -Expectation $block).Status | Should -Be 'Pass'
        (Test-ResCaExpectation -Outcome (New-Outcome 'Block') -Expectation ([pscustomobject]@{ Expect = 'Info'; Severity = 'Info' })).Status | Should -Be 'Investigate'
    }
    It 'requires phishing resistance only when asked' {
        $pr = [pscustomobject]@{ Expect = 'PhishingResistant'; Severity = 'Critical' }
        (Test-ResCaExpectation -Outcome (New-Outcome 'MFA') -Expectation $pr).Status | Should -Be 'Fail'
        (Test-ResCaExpectation -Outcome (New-Outcome 'PhishingResistant') -Expectation $pr).Status | Should -Be 'Pass'
    }
}

Describe 'Get-ResCaAxis' {
    BeforeAll {
        $policies = @(
            [pscustomobject]@{ state = 'enabled'; conditions = [pscustomobject]@{ applications = [pscustomobject]@{ includeApplications = @('11111111-2222-3333-4444-555555555555', 'All'); excludeApplications = @(); includeUserActions = @('urn:user:registerSecurityInformation') }; platforms = [pscustomobject]@{ includePlatforms = @('iOS'); excludePlatforms = @('windows') } } },
            [pscustomobject]@{ state = 'disabled'; conditions = [pscustomobject]@{ applications = [pscustomobject]@{ includeApplications = @('99999999-2222-3333-4444-555555555555'); excludeApplications = @(); includeUserActions = @() }; platforms = $null } }
        )
        $locations = @(
            [pscustomobject]@{ '@odata.type' = '#microsoft.graph.countryNamedLocation'; countriesAndRegions = @('GB', 'IE', 'FR') },
            [pscustomobject]@{ '@odata.type' = '#microsoft.graph.ipNamedLocation'; isTrusted = $true; ipRanges = @([pscustomobject]@{ cidrAddress = '198.51.100.0/24' }) }
        )
    }
    It 'omits risk axes without P2 and says why' {
        $axis = Get-ResCaAxis -Policy $policies -NamedLocation $locations -P2Licensed $false
        $axis.SignInRiskLevels.Count | Should -Be 0
        $axis.UserRiskLevels.Count | Should -Be 0
        ($axis.Notes -join ' ') | Should -Match 'Risk axes omitted: Entra ID P2 not licensed'
    }
    It 'adds risk axes with P2' {
        $axis = Get-ResCaAxis -Policy $policies -NamedLocation $locations -P2Licensed $true
        $axis.SignInRiskLevels | Should -Be @('High')
        $axis.UserRiskLevels | Should -Be @('High')
    }
    It 'keeps the home-location note short however many countries a block policy matches' {
        $codes = @(foreach ($a in [char[]]'ABCDEFGHIJ') { foreach ($b in [char[]]'ABCDEFGHIJKLMNOPQRST') { "$a$b" } })
        $loc = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.countryNamedLocation'; id = 'loc1'; countriesAndRegions = $codes }
        $blockPolicy = [pscustomobject]@{ state = 'enabled'; displayName = 'Block everywhere else'; grantControls = [pscustomobject]@{ builtInControls = @('block') }; conditions = [pscustomobject]@{ applications = [pscustomobject]@{ includeApplications = @('All'); excludeApplications = @(); includeUserActions = @() }; platforms = $null; locations = [pscustomobject]@{ includeLocations = @('loc1'); excludeLocations = @() } } }
        $axis = Get-ResCaAxis -Policy @($blockPolicy) -NamedLocation @($loc) -P2Licensed $false
        $note = @($axis.Notes | Where-Object { $_ -like 'Home location*' })[0]
        $note | Should -Match 'Skipped as home: 200 countries'
        $note.Length | Should -BeLessThan 1000
    }
    It 'caps a scenario result so the Maester CSV export stays fast' {
        Mock Invoke-MtGraphRequest { @() }
        $persona = [pscustomobject]@{ Key = 'member-c01'; Kind = 'Member'; Label = 'Member:class-1'; UserId = 'm'; UserPrincipalName = 'm@c.com'; ClassSize = 3; ClassPolicies = @(); IsEmergencyAccess = $false }
        $app = [pscustomobject]@{ Key = 'exo'; Name = 'Office 365 Exchange Online'; Id = '00000002-0000-0ff1-ce00-000000000000'; Group = 'Other' }
        $scenario = [pscustomobject]@{ Persona = $persona; App = $app; UserAction = $null; ClientAppType = 'browser'; DevicePlatform = 'windows'; Country = 'US'; IpAddress = $null; LocationKey = 'home'; SignInRiskLevel = 'None'; UserRiskLevel = 'None' }
        $text = Format-ResCaResult -Scenario $scenario -Outcome (Get-ResCaOutcome -Result @()) -Expectation ([pscustomobject]@{ Expect = 'Info'; Severity = 'Info'; Source = 'Default'; Note = '' }) -Verdict ([pscustomobject]@{ Status = 'Investigate'; Reason = 'r'; Severity = $null }) -Cache @{} -Note @('x' * 50000)
        $text.Length | Should -BeLessThan 21000
    }
    It 'treats unknown P2 as not licensed' {
        (Get-ResCaAxis -Policy $policies -P2Licensed $null).SignInRiskLevels.Count | Should -Be 0
    }
    It 'takes apps, platforms, user actions and locations from the policies' {
        $axis = Get-ResCaAxis -Policy $policies -NamedLocation $locations -P2Licensed $false
        $axis.Apps.Id | Should -Contain '11111111-2222-3333-4444-555555555555'
        $axis.Apps.Id | Should -Not -Contain '99999999-2222-3333-4444-555555555555'
        $axis.Apps.Id | Should -Contain '00000002-0000-0ff1-ce00-000000000000'
        $axis.Platforms | Should -Contain 'iOS'
        $axis.Platforms | Should -Contain 'windows'
        $axis.UserActions | Should -Be @('registerSecurityInformation')
        $home1 = $axis.Locations | Where-Object { $_.Key -eq 'home' }
        $home1.Country | Should -Be 'GB'
        $home1.IpAddress | Should -Be '198.51.100.1'
        ($axis.Locations | Where-Object { $_.Key -eq 'outside' }).Country | Should -Not -BeIn @('GB', 'IE', 'FR')
        ($axis.Locations | Where-Object { $_.Key -eq 'outside' }).IpAddress | Should -Be '203.0.113.10'
    }
    It 'always probes the legacy client types and falls back to default platforms' {
        $axis = Get-ResCaAxis -Policy @() -P2Licensed $false
        $axis.ClientTypes | Should -Contain 'exchangeActiveSync'
        $axis.ClientTypes | Should -Contain 'other'
        $axis.Platforms.Count | Should -Be 4
    }
    It 'caps explicit apps and says so' {
        $many = @([pscustomobject]@{ state = 'enabled'; conditions = [pscustomobject]@{ applications = [pscustomobject]@{ includeApplications = @(1..5 | ForEach-Object { '{0}0000000-2222-3333-4444-555555555555' -f $_ }); excludeApplications = @(); includeUserActions = @() }; platforms = $null } })
        $axis = Get-ResCaAxis -Policy $many -P2Licensed $false -MaxExplicitApps 2
        @($axis.Apps | Where-Object { $_.Group -eq 'Other' }).Count | Should -Be 2
        ($axis.Notes -join ' ') | Should -Match 'MaxExplicitApps'
    }
}

Describe 'New-ResCaScenario and Select-ResCaScenario' {
    BeforeAll {
        $axis = Get-ResCaAxis -Policy @() -P2Licensed $true
        $priv = [pscustomobject]@{ Key = 'priv-01'; Kind = 'Privileged'; Label = 'Privileged:GlobalAdministrator'; UserId = 'a'; UserPrincipalName = 'a@c.com'; IsEmergencyAccess = $false }
        $member = [pscustomobject]@{ Key = 'member-c01'; Kind = 'Member'; Label = 'Member:class-1'; UserId = 'm'; UserPrincipalName = 'm@c.com'; IsEmergencyAccess = $false }
        $scenarios = @(New-ResCaScenario -Persona @($member, $priv) -Axis $axis)
    }
    It 'sets every condition explicitly on every scenario' {
        foreach ($s in $scenarios) {
            $s.ClientAppType | Should -Not -BeNullOrEmpty
            $s.DevicePlatform | Should -Not -BeNullOrEmpty
            $s.Country | Should -Not -BeNullOrEmpty
            $s.SignInRiskLevel | Should -Not -BeNullOrEmpty
            $s.UserRiskLevel | Should -Not -BeNullOrEmpty
        }
    }
    It 'has unique keys' { ($scenarios.Key | Select-Object -Unique).Count | Should -Be $scenarios.Count }
    It 'orders privileged legacy scenarios first and informational member scenarios last' {
        $scenarios[0].Persona.Kind | Should -Be 'Privileged'
        $scenarios[0].ClientAppType | Should -BeIn @('exchangeActiveSync', 'other')
        $scenarios[-1].Priority | Should -Be 9
    }
    It 'adds risk scenarios only with risk levels on the axis' {
        @($scenarios | Where-Object { $_.Axis -eq 'risk' }).Count | Should -BeGreaterThan 0
        $noRisk = @(New-ResCaScenario -Persona @($priv) -Axis (Get-ResCaAxis -Policy @() -P2Licensed $false))
        @($noRisk | Where-Object { $_.Axis -eq 'risk' }).Count | Should -Be 0
        @($noRisk | Where-Object { $_.SignInRiskLevel -ne 'None' -or $_.UserRiskLevel -ne 'None' }).Count | Should -Be 0
    }
    It 'caps round-robin by persona and reports how many were cut' {
        $kept = @(Select-ResCaScenario -Scenario $scenarios -MaxScenarios 10)
        $kept.Count | Should -Be 10
        $kept[0].Truncated | Should -Be ($scenarios.Count - 10)
        ($kept | Where-Object { $_.Persona.Kind -eq 'Privileged' }).Count | Should -BeGreaterOrEqual 5
        ($kept | Where-Object { $_.Persona.Kind -eq 'Member' }).Count | Should -BeGreaterOrEqual 4
    }
    It 'reports no truncation under the cap' {
        (Select-ResCaScenario -Scenario $scenarios -MaxScenarios 100000)[0].Truncated | Should -Be 0
    }
}

Describe 'Invoke-ResCaWhatIf' {
    BeforeAll {
        $scenario = [pscustomobject]@{ Key = 'k1'; Persona = [pscustomobject]@{ UserId = '00000000-0000-0000-0000-000000000001' }; App = [pscustomobject]@{ Id = '00000002-0000-0ff1-ce00-000000000000' }; UserAction = $null; ClientAppType = 'browser'; DevicePlatform = 'windows'; Country = 'GB'; IpAddress = $null; SignInRiskLevel = 'None'; UserRiskLevel = 'None' }
    }
    It 'serves a repeated scenario from the cache' {
        Mock Test-MtConditionalAccessWhatIf { @([pscustomobject]@{ id = 'p' }) }
        Mock Start-Sleep { }
        $cache = @{}
        $null = Invoke-ResCaWhatIf -Scenario $scenario -Cache $cache -ThrottleMilliseconds 0
        $null = Invoke-ResCaWhatIf -Scenario $scenario -Cache $cache -ThrottleMilliseconds 0
        Should -Invoke Test-MtConditionalAccessWhatIf -Times 1 -Exactly
    }
    It 'passes every condition and asks for all results' {
        Mock Test-MtConditionalAccessWhatIf { @() }
        Mock Start-Sleep { }
        $null = Invoke-ResCaWhatIf -Scenario $scenario -Cache @{} -ThrottleMilliseconds 0
        Should -Invoke Test-MtConditionalAccessWhatIf -Times 1 -Exactly -ParameterFilter { $AllResults -and $ClientAppType -eq 'browser' -and $DevicePlatform -eq 'windows' -and $Country -eq 'GB' -and $SignInRiskLevel -eq 'None' -and $UserRiskLevel -eq 'None' -and $IncludeApplications -eq '00000002-0000-0ff1-ce00-000000000000' }
    }
    It 'retries a 429 and then succeeds' {
        $script:calls = 0
        Mock Test-MtConditionalAccessWhatIf { $script:calls++; if ($script:calls -lt 3) { throw 'Response status code does not indicate success: 429 (TooManyRequests).' }; @([pscustomobject]@{ id = 'ok' }) }
        Mock Start-Sleep { }
        (Invoke-ResCaWhatIf -Scenario $scenario -Cache @{} -ThrottleMilliseconds 0)[0].id | Should -Be 'ok'
        $script:calls | Should -Be 3
    }
    It 'does not retry other errors' {
        Mock Test-MtConditionalAccessWhatIf { throw 'Forbidden' }
        Mock Start-Sleep { }
        { Invoke-ResCaWhatIf -Scenario $scenario -Cache @{} -ThrottleMilliseconds 0 } | Should -Throw
        Should -Invoke Test-MtConditionalAccessWhatIf -Times 1 -Exactly
    }
}

Describe 'Get-ResCaPersonaSet' {
    BeforeAll {
        function Test-ResLicense { param($ServicePlan) $true }
        function Get-ResPrivilegedUser { param([switch]$ActiveOnly) [pscustomobject]@{ Id = 'admin1'; UserPrincipalName = 'admin@contoso.com'; DisplayName = 'Admin'; Roles = @('Global Administrator'); EligibleReadable = $false } }
    }
    BeforeEach {
        Mock Get-MtConditionalAccessPolicy {
            @(
                (New-Policy -Id 'p1' -Users @{ includeUsers = @('All'); excludeGroups = @('g-exempt') }),
                (New-Policy -Id 'p2' -State 'enabledForReportingButNotEnforced' -Users @{ includeUsers = @('All') }),
                (New-Policy -Id 'p3' -State 'disabled' -Users @{ includeUsers = @('All') })
            )
        }
        Mock Get-MtSetting { @() }
        Mock Invoke-MtGraphRequest {
            switch -Wildcard ($RelativeUri) {
                'identity/conditionalAccess/namedLocations' { @() }
                'users' { @(@{ id = 'admin1'; userPrincipalName = 'admin@contoso.com'; displayName = 'Admin'; userType = 'Member' }, @{ id = 'u1'; userPrincipalName = 'u1@contoso.com'; displayName = 'U1'; userType = 'Member' }, @{ id = 'u2'; userPrincipalName = 'u2@contoso.com'; displayName = 'U2'; userType = 'Member' }, @{ id = 'u3'; userPrincipalName = 'u3@contoso.com'; displayName = 'U3'; userType = 'Member' }) | ForEach-Object { [pscustomobject]$_ } }
                'groups/g-exempt/transitiveMembers/*' { [pscustomobject]@{ id = 'u3' } }
                'roleManagement/directory/roleAssignments' { @() }
                default { @() }
            }
        }
    }
    It 'reads enabled and report-only policies, never disabled ones, and groups users into personas' {
        $set = Get-ResCaPersonaSet
        @($set.Policies).Count | Should -Be 2
        $kinds = @($set.Personas | Group-Object Kind -AsHashTable -AsString)
        @($set.Personas | Where-Object { $_.Kind -eq 'Privileged' }).Count | Should -Be 1
        @($set.Personas | Where-Object { $_.Kind -eq 'Member' }).Count | Should -Be 2
        ($set.Notes -join ' ') | Should -Match 'Eligible \(PIM\)'
    }
    It 'leaves report-only policies out when asked' {
        $set = Get-ResCaPersonaSet -IncludeReportOnly $false
        @($set.Policies).Count | Should -Be 1
    }
    It 'writes the persona file and reads it back without reading users again' {
        $file = Join-Path $TestDrive 'personas.json'
        $first = Get-ResCaPersonaSet -PersonaFile $file
        Test-Path $file | Should -BeTrue
        Mock Invoke-MtGraphRequest { if ($RelativeUri -eq 'users') { throw 'users must not be read' }; @() }
        $second = Get-ResCaPersonaSet -PersonaFile $file
        $second.FromFile | Should -BeTrue
        @($second.Personas).Count | Should -Be @($first.Personas).Count
    }
    It 'reads the tenant again when asked to refresh' {
        $file = Join-Path $TestDrive 'personas2.json'
        $null = Get-ResCaPersonaSet -PersonaFile $file
        (Get-ResCaPersonaSet -PersonaFile $file -RefreshPersonas $true).FromFile | Should -BeFalse
    }
    It 'says so when the user cap cuts the sample' {
        $set = Get-ResCaPersonaSet -MaxUsers 2
        ($set.Notes -join ' ') | Should -Match 'only the first 2'
    }
}


Describe 'Get-ResCaAxis platforms, home location and notes' {
    BeforeAll {
        function New-LocPolicy { param($Name, $State = 'enabled', $Include = @(), $Exclude = @(), $Controls = @('mfa'), $Platforms = $null)
            [pscustomobject]@{ id = $Name; displayName = $Name; state = $State; grantControls = [pscustomobject]@{ operator = 'OR'; builtInControls = $Controls }
                conditions = [pscustomobject]@{ applications = [pscustomobject]@{ includeApplications = @('All'); excludeApplications = @(); includeUserActions = @() }; platforms = $Platforms
                    locations = [pscustomobject]@{ includeLocations = $Include; excludeLocations = $Exclude } } } }
        function New-Country { param($Id, $Codes) [pscustomobject]@{ '@odata.type' = '#microsoft.graph.countryNamedLocation'; id = $Id; displayName = $Id; countriesAndRegions = $Codes } }
    }
    It 'always probes windows, iOS, Android and macOS even when a policy names only Android' {
        $p = New-LocPolicy -Name 'android only' -Platforms ([pscustomobject]@{ includePlatforms = @('android'); excludePlatforms = @() })
        $axis = Get-ResCaAxis -Policy @($p) -P2Licensed $false
        foreach ($x in 'windows', 'iOS', 'Android', 'macOS') { $axis.Platforms | Should -Contain $x }
        $axis.Platforms.Count | Should -Be 4
        $axis.Platforms[0] | Should -Be 'windows'
    }
    It 'adds other platforms that a policy names' {
        $p = New-LocPolicy -Name 'linux' -Platforms ([pscustomobject]@{ includePlatforms = @('linux', 'windowsPhone'); excludePlatforms = @() })
        $axis = Get-ResCaAxis -Policy @($p) -P2Licensed $false
        $axis.Platforms | Should -Contain 'linux'
        $axis.Platforms | Should -Contain 'windowsPhone'
        $axis.Platforms.Count | Should -Be 6
        ($axis.Notes -join ' ') | Should -Match 'Platforms probed: windows, iOS, Android and macOS always, plus'
    }
    It 'uses windows as the base platform even when it is not first on the axis' {
        $axis = [pscustomobject]@{ Apps = @(Get-ResCaWellKnownApp); LegacyProbes = @(); Platforms = @('Android', 'iOS', 'windows', 'macOS'); UserActions = @(); SignInRiskLevels = @(); UserRiskLevels = @()
            Locations = @([pscustomobject]@{ Key = 'home'; Country = 'US'; IpAddress = $null }, [pscustomobject]@{ Key = 'outside'; Country = 'RU'; IpAddress = $null }) }
        $persona = [pscustomobject]@{ Key = 'member-c01'; Kind = 'Member'; Label = 'Member:class-1'; UserId = 'm'; UserPrincipalName = 'm@c.com'; IsEmergencyAccess = $false }
        $s = @(New-ResCaScenario -Persona @($persona) -Axis $axis)
        ($s | Where-Object { $_.Axis -eq 'baseline' }).DevicePlatform | Select-Object -Unique | Should -Be 'windows'
        ($s | Where-Object { $_.Axis -eq 'platform' }).DevicePlatform | Should -Not -Contain 'windows'
    }
    It 'chooses a home country that no block or location-conditioned policy matches' {
        $locs = @((New-Country 'loc-gb' @('GB')), (New-Country 'loc-ie' @('IE')))
        $policies = @(
            (New-LocPolicy -Name 'Geoblock GB' -State 'enabledForReportingButNotEnforced' -Include @('loc-gb') -Controls @('block')),
            (New-LocPolicy -Name 'MFA outside' -Include @('All') -Exclude @('loc-ie')))
        $axis = Get-ResCaAxis -Policy $policies -NamedLocation $locs -P2Licensed $false
        ($axis.Locations | Where-Object { $_.Key -eq 'home' }).Country | Should -Be 'IE'
        ($axis.Notes -join ' ') | Should -Match 'Home location: IE chosen'
        ($axis.Notes -join ' ') | Should -Match 'Skipped as home: 1 country \(GB\), matched by Geoblock GB \(block, report-only\)'
    }
    It 'treats a country that a block policy allow-lists as blocked for everyone else' {
        $locs = @((New-Country 'loc-gb' @('GB')), (New-Country 'loc-fr' @('FR')))
        $policies = @((New-LocPolicy -Name 'Block outside GB' -Include @('All') -Exclude @('loc-gb') -Controls @('block')))
        $axis = Get-ResCaAxis -Policy $policies -NamedLocation $locs -P2Licensed $false
        ($axis.Locations | Where-Object { $_.Key -eq 'home' }).Country | Should -Be 'GB'
    }
    It 'falls back to the neutral default US when every named location collides, and says why' {
        $locs = @((New-Country 'loc-gb' @('GB')))
        $policies = @((New-LocPolicy -Name 'Geoblock' -Include @('loc-gb') -Controls @('block')))
        $axis = Get-ResCaAxis -Policy $policies -NamedLocation $locs -P2Licensed $false
        ($axis.Locations | Where-Object { $_.Key -eq 'home' }).Country | Should -Be 'US'
        ($axis.Notes -join ' ') | Should -Match 'Home location: US chosen as a neutral default, because every named-location country is matched'
    }
    It 'states which service plan decided the risk axes' {
        $on = (Get-ResCaAxis -Policy @() -P2Licensed $true).Notes -join ' '
        $on | Should -Match 'Risk axes probed \(Entra ID P2 present\)'
        $on | Should -Match 'AAD_PREMIUM_P2 was found'
        $off = (Get-ResCaAxis -Policy @() -P2Licensed $false).Notes -join ' '
        $off | Should -Match 'Risk axes omitted: Entra ID P2 not licensed'
        $off | Should -Match 'AAD_PREMIUM_P2 was not found'
        ((Get-ResCaAxis -Policy @() -P2Licensed $null).Notes -join ' ') | Should -Match 'could not be read'
    }
    It 'probes legacy clients against Exchange Online, one representative app and apps that legacy policies name' {
        $explicit = '11111111-2222-3333-4444-555555555555'
        $legacyPolicy = [pscustomobject]@{ state = 'enabled'; conditions = [pscustomobject]@{ clientAppTypes = @('other'); applications = [pscustomobject]@{ includeApplications = @($explicit); excludeApplications = @(); includeUserActions = @() }; platforms = $null } }
        $axis = Get-ResCaAxis -Policy @($legacyPolicy) -P2Licensed $false
        ($axis.LegacyProbes | Where-Object { $_.AppKey -eq 'exo' }).ClientTypes | Should -Be @('exchangeActiveSync', 'other')
        ($axis.LegacyProbes | Where-Object { $_.AppKey -eq 'spo' }).ClientTypes | Should -Be @('other')
        $axis.LegacyProbes.AppKey | Should -Contain $explicit.Substring(0, 8)
        $axis.LegacyProbes.AppKey | Should -Not -Contain 'arm'
        $persona = [pscustomobject]@{ Key = 'member-c01'; Kind = 'Member'; Label = 'Member:class-1'; UserId = 'm'; UserPrincipalName = 'm@c.com'; IsEmergencyAccess = $false }
        $legacy = @(New-ResCaScenario -Persona @($persona) -Axis $axis | Where-Object { $_.Axis -eq 'client' })
        $legacy.Count | Should -Be 4
        @($legacy | Where-Object { $_.App.Key -eq 'exo' }).Count | Should -Be 2
    }
}

Describe 'Round-robin cap' {
    BeforeAll {
        $axis = Get-ResCaAxis -Policy @() -P2Licensed $true
        $personas = @(
            [pscustomobject]@{ Key = 'priv-01'; Kind = 'Privileged'; Label = 'Privileged:GA'; UserId = 'a'; UserPrincipalName = 'a@c.com'; IsEmergencyAccess = $false },
            [pscustomobject]@{ Key = 'member-c01'; Kind = 'Member'; Label = 'Member:class-1'; UserId = 'm'; UserPrincipalName = 'm@c.com'; IsEmergencyAccess = $false },
            [pscustomobject]@{ Key = 'member-c02'; Kind = 'Member'; Label = 'Member:class-2'; UserId = 'n'; UserPrincipalName = 'n@c.com'; IsEmergencyAccess = $false },
            [pscustomobject]@{ Key = 'guest-c01'; Kind = 'Guest'; Label = 'Guest:class-1'; UserId = 'g'; UserPrincipalName = 'g@c.com'; IsEmergencyAccess = $false })
        $all = @(New-ResCaScenario -Persona $personas -Axis $axis)
    }
    It 'gives every persona a legacy probe, a baseline, a platform and a location scenario under a small cap' {
        $kept = @(Select-ResCaScenario -Scenario $all -MaxScenarios 16)
        $kept.Count | Should -Be 16
        foreach ($p in $personas) {
            $mine = @($kept | Where-Object { $_.PersonaKey -eq $p.Key })
            @($mine | Where-Object { $_.Axis -eq 'client' -and $_.ClientAppType -eq 'exchangeActiveSync' }).Count | Should -BeGreaterThan 0
            @($mine | Where-Object { $_.Axis -eq 'baseline' -and $_.ClientAppType -eq 'browser' }).Count | Should -BeGreaterThan 0
            @($mine | Where-Object { $_.Axis -eq 'platform' }).Count | Should -BeGreaterThan 0
            @($mine | Where-Object { $_.Axis -eq 'location' }).Count | Should -BeGreaterThan 0
            $mine.Count | Should -Be 4
        }
    }
    It 'gives nobody a second scenario of anything before everyone has the core set, privileged first' {
        $kept = @(Select-ResCaScenario -Scenario $all -MaxScenarios 18)
        @($kept | Where-Object { $_.Round -eq 2 }).Count | Should -Be 2
        @($kept | Where-Object { $_.Round -eq 2 }).Persona.Kind | Should -Not -Contain 'Guest'
        $tiny = @(Select-ResCaScenario -Scenario $all -MaxScenarios 3)
        $tiny.PersonaKey | Should -Not -Contain 'guest-c01'
        @($tiny | Where-Object { $_.Axis -eq 'client' }).Count | Should -Be 3
        $four = @(Select-ResCaScenario -Scenario $all -MaxScenarios 4)
        @($four | Where-Object { $_.Axis -eq 'client' -and $_.ClientAppType -eq 'exchangeActiveSync' }).Count | Should -Be 4
    }
    It 'names the personas that lost axes' {
        $kept = @(Select-ResCaScenario -Scenario $all -MaxScenarios 16)
        $notes = @(Get-ResCaTruncationNote -All $all -Kept $kept)
        $notes.Count | Should -Be 4
        $notes[0].Text | Should -Match 'lost \d+ scenarios to the cap: .*platforms'
        @(Get-ResCaTruncationNote -All $all -Kept $all).Count | Should -Be 0
    }
}

Describe 'AppRequired, report-only location block and legacy de facto block' {
    BeforeAll {
        function New-Outcome2 { param($Class, $Flags = @(), $ReportOnlyClass = 'NoControl', $Depends = $false) [pscustomobject]@{ Class = $Class; Flags = $Flags; ReportOnlyClass = $ReportOnlyClass; CoverageDependsOnReportOnly = $Depends; NotAssessedPolicies = @(); Failure = $null } }
    }
    It 'classifies an approved app requirement as AppRequired, not NoControl' {
        (Get-ResCaOutcome -Result @(New-Policy -Id 'p1' -Grant (New-Grant -Controls @('approvedApplication', 'compliantApplication') -Operator 'OR'))).Class | Should -Be 'AppRequired'
        (Get-ResCaOutcome -Result @(New-Policy -Id 'p1' -Grant (New-Grant -Controls @('compliantDevice', 'approvedApplication')))).Class | Should -Be 'DeviceRequired'
        $mfaAndApp = Get-ResCaOutcome -Result @(New-Policy -Id 'p1' -Grant (New-Grant -Controls @('mfa', 'approvedApplication') -Operator 'AND'))
        $mfaAndApp.Class | Should -Be 'MFA'
    }
    It 'does not let AppRequired satisfy an MFA expectation' {
        (Test-ResCaExpectation -Outcome (New-Outcome2 'AppRequired' @('App')) -Expectation ([pscustomobject]@{ Expect = 'MFA'; Severity = 'High' })).Status | Should -Be 'Investigate'
    }
    It 'does not make a report-only location block alone a reason for coverage depends on report-only' {
        $row = New-Policy -Id 'geo' -State 'enabledForReportingButNotEnforced' -Grant (New-Grant -Controls @('block'))
        $row.conditions | Add-Member -NotePropertyName locations -NotePropertyValue ([pscustomobject]@{ includeLocations = @('loc-ru'); excludeLocations = @() })
        $o = Get-ResCaOutcome -Result @($row)
        $o.CoverageDependsOnReportOnly | Should -BeFalse
        @($o.ReportOnly).Count | Should -Be 1
        @($o.ReportOnlyLocationBlock).Count | Should -Be 1
        (Test-ResCaExpectation -Outcome $o -Expectation ([pscustomobject]@{ Expect = 'MFA'; Severity = 'High' })).Status | Should -Be 'Fail'
    }
    It 'finds the location condition from the tenant policies when the row has none' {
        $row = New-Policy -Id 'geo' -State 'enabledForReportingButNotEnforced' -Grant (New-Grant -Controls @('block'))
        $tenant = New-Policy -Id 'geo' -State 'enabledForReportingButNotEnforced' -Grant (New-Grant -Controls @('block'))
        $tenant.conditions | Add-Member -NotePropertyName locations -NotePropertyValue ([pscustomobject]@{ includeLocations = @('loc-ru'); excludeLocations = @() })
        (Get-ResCaOutcome -Result @($row) -Policy @($tenant)).CoverageDependsOnReportOnly | Should -BeFalse
        (Get-ResCaOutcome -Result @($row)).CoverageDependsOnReportOnly | Should -BeTrue
    }
    It 'still counts a report-only MFA policy as coverage that depends on report-only' {
        (Get-ResCaOutcome -Result @(New-Policy -Id 'p' -State 'enabledForReportingButNotEnforced' -Grant (New-Grant -Controls @('mfa')))).CoverageDependsOnReportOnly | Should -BeTrue
    }
    It 'treats MFA, device and app requirements on a legacy client as a de facto block with Low severity' {
        $block = [pscustomobject]@{ Expect = 'Block'; Severity = 'Critical' }
        foreach ($class in 'MFA', 'PhishingResistant', 'DeviceRequired', 'AppRequired') {
            $v = Test-ResCaExpectation -Outcome (New-Outcome2 $class) -Expectation $block -ClientAppType 'exchangeActiveSync'
            $v.Status | Should -Be 'Pass'
            $v.Severity | Should -Be 'Low'
            $v.Reason | Should -Match 'de facto block, an explicit block policy is still recommended'
        }
        (Test-ResCaExpectation -Outcome (New-Outcome2 'MFA') -Expectation $block -ClientAppType 'other').Status | Should -Be 'Pass'
    }
    It 'keeps literal NoControl on a legacy client as the failure, and MFA on a modern client as a failure of a Block expectation' {
        $block = [pscustomobject]@{ Expect = 'Block'; Severity = 'Critical' }
        (Test-ResCaExpectation -Outcome (New-Outcome2 'NoControl') -Expectation $block -ClientAppType 'exchangeActiveSync').Status | Should -Be 'Fail'
        (Test-ResCaExpectation -Outcome (New-Outcome2 'MFA') -Expectation $block -ClientAppType 'browser').Status | Should -Be 'Fail'
        (Test-ResCaExpectation -Outcome (New-Outcome2 'Block') -Expectation $block -ClientAppType 'other').Severity | Should -BeNullOrEmpty
    }
}

Describe 'Invoke-ResCaWhatIf transient errors' {
    BeforeAll {
        $scenario = [pscustomobject]@{ Key = 'k500'; Persona = [pscustomobject]@{ UserId = '00000000-0000-0000-0000-000000000001' }; App = [pscustomobject]@{ Id = '00000002-0000-0ff1-ce00-000000000000' }; UserAction = $null; ClientAppType = 'browser'; DevicePlatform = 'windows'; Country = 'GB'; IpAddress = $null; SignInRiskLevel = 'None'; UserRiskLevel = 'None' }
    }
    It 'retries HTTP 500 and 502 and then succeeds' {
        foreach ($code in '500 (InternalServerError)', '502 (BadGateway)', '503 (ServiceUnavailable)', '504 (GatewayTimeout)') {
            $script:calls = 0
            $script:code = $code
            Mock Test-MtConditionalAccessWhatIf { $script:calls++; if ($script:calls -lt 3) { throw "Response status code does not indicate success: $($script:code)." }; @([pscustomobject]@{ id = 'ok' }) }
            Mock Start-Sleep { }
            (Invoke-ResCaWhatIf -Scenario $scenario -Cache @{} -ThrottleMilliseconds 0)[0].id | Should -Be 'ok'
            $script:calls | Should -Be 3
        }
    }
    It 'returns a not-assessed row instead of throwing when retries are exhausted, and does not cache it' {
        Mock Test-MtConditionalAccessWhatIf { throw 'Response status code does not indicate success: 500 (InternalServerError).' }
        Mock Start-Sleep { }
        $cache = @{}
        $rows = Invoke-ResCaWhatIf -Scenario $scenario -Cache $cache -ThrottleMilliseconds 0
        Should -Invoke Test-MtConditionalAccessWhatIf -Times 4 -Exactly
        @($rows).Count | Should -Be 1
        $rows[0].resCaError | Should -Match '500'
        $cache.ContainsKey('k500') | Should -BeFalse
        $outcome = Get-ResCaOutcome -Result $rows
        $outcome.Class | Should -Be 'NotAssessed'
        $verdict = Test-ResCaExpectation -Outcome $outcome -Expectation ([pscustomobject]@{ Expect = 'Block'; Severity = 'High' })
        $verdict.Status | Should -Be 'Investigate'
        $verdict.Reason | Should -Match 'failed after retries'
    }
    It 'retries a timeout' {
        $script:calls = 0
        Mock Test-MtConditionalAccessWhatIf { $script:calls++; if ($script:calls -lt 2) { throw 'The request was canceled due to the configured HttpClient.Timeout.' }; @() }
        Mock Start-Sleep { }
        $null = Invoke-ResCaWhatIf -Scenario $scenario -Cache @{} -ThrottleMilliseconds 0
        $script:calls | Should -Be 2
    }
}

Describe 'Emergency accounts, privileged note and application names' {
    BeforeAll {
        function Test-ResLicense { param($ServicePlan) $true }
        function Get-ResPrivilegedUser { param([switch]$ActiveOnly) }
    }
    It 'recognises an emergency account in a class, keeps it out of the representative pool and tests it on its own' {
        $policies = @((New-Policy -Id 'p1' -Users @{ includeUsers = @('All') }))
        $users = @((New-User 'a-break'), (New-User 'b'), (New-User 'c'))
        $classes = @(Group-ResCaUserByScope -User $users -Policy $policies)
        $p = @(Select-ResCaPersona -Class $classes -PrivilegedUser @() -EmergencyAccess @('A-break@contoso.com'))
        $rep = @($p | Where-Object { $_.Kind -eq 'Member' -and -not $_.IsEmergencyAccess })
        $rep.Count | Should -Be 1
        $rep[0].UserPrincipalName | Should -Be 'b@contoso.com'
        $rep[0].ClassSize | Should -Be 2
        $em = @($p | Where-Object { $_.IsEmergencyAccess })
        $em.Count | Should -Be 1
        $em[0].UserPrincipalName | Should -Be 'a-break@contoso.com'
        $em[0].Key | Should -Be 'emerg-01'
        (Get-ResCaExpectation -Scenario ([pscustomobject]@{ Persona = $em[0]; App = $null; ClientAppType = 'browser'; DevicePlatform = 'windows'; LocationKey = 'home'; UserAction = $null; Axis = 'baseline'; SignInRiskLevel = 'None'; UserRiskLevel = 'None' }) -Desired $null).Expect | Should -Be 'Info'
    }
    It 'matches an emergency account by object ID and drops a class that holds only emergency accounts' {
        $classes = @(Group-ResCaUserByScope -User @((New-User 'only')) -Policy @((New-Policy -Id 'p1' -Users @{ includeUsers = @('All') })))
        $p = @(Select-ResCaPersona -Class $classes -PrivilegedUser @() -EmergencyAccess @('ONLY'))
        @($p | Where-Object { -not $_.IsEmergencyAccess }).Count | Should -Be 0
        @($p | Where-Object { $_.IsEmergencyAccess }).Count | Should -Be 1
    }
    It 'adds a visible note when no privileged user is found, and one for emergency accounts' {
        Mock Get-MtConditionalAccessPolicy { @((New-Policy -Id 'p1' -Users @{ includeUsers = @('All') })) }
        Mock Get-MtSetting { @([pscustomobject]@{ UserPrincipalName = 'u1@contoso.com' }) }
        Mock Invoke-MtGraphRequest {
            if ($RelativeUri -eq 'users') { @('u1', 'u2') | ForEach-Object { [pscustomobject]@{ id = $_; userPrincipalName = "$_@contoso.com"; displayName = $_; userType = 'Member' } } } else { @() }
        }
        $set = Get-ResCaPersonaSet
        ($set.Notes -join ' ') | Should -Match '0 privileged users were found.*no Critical expectation applied'
        ($set.Notes -join ' ') | Should -Match '1 emergency access accounts'
        @($set.Personas | Where-Object { $_.IsEmergencyAccess }).Count | Should -Be 1
    }
    It 'resolves application display names, caches them and falls back to the GUID' {
        $id = '11111111-2222-3333-4444-555555555555'
        $bad = '99999999-2222-3333-4444-555555555555'
        $script:goodId = $id
        Mock Invoke-MtGraphRequest { if ($Filter -like "*$($script:goodId)*") { [pscustomobject]@{ appId = $script:goodId; displayName = 'Contoso HR' } } else { throw 'boom' } }
        $cache = @{}
        $names = Resolve-ResCaAppName -AppId @($id, $bad, '00000002-0000-0ff1-ce00-000000000000', 'All') -Cache $cache
        $names[$id] | Should -Be 'Contoso HR'
        $names[$bad] | Should -Be $bad
        $names['00000002-0000-0ff1-ce00-000000000000'] | Should -Be 'Office 365 Exchange Online'
        $names['All'] | Should -Be 'All'
        $null = Resolve-ResCaAppName -AppId @($id, $bad) -Cache $cache
        Should -Invoke Invoke-MtGraphRequest -Times 2 -Exactly
        Should -Invoke Invoke-MtGraphRequest -Times 1 -Exactly -ParameterFilter { $RelativeUri -eq 'servicePrincipals' -and $Filter -eq "appId eq '$id'" }
    }
    It 'shows the app name, class size and including and excluding policies in the row text' {
        $id = '11111111-2222-3333-4444-555555555555'
        Mock Invoke-MtGraphRequest { [pscustomobject]@{ appId = $id; displayName = 'Contoso HR' } }
        $persona = [pscustomobject]@{ Key = 'member-c01'; Kind = 'Member'; Label = 'Member:class-1'; UserId = 'm'; UserPrincipalName = 'm@c.com'; ClassSize = 42; ClassPolicies = @('MFA all (Included)', 'Exempt (Excluded)'); IsEmergencyAccess = $false }
        $scenario = [pscustomobject]@{ Persona = $persona; App = [pscustomobject]@{ Key = $id.Substring(0, 8); Name = "Application $id"; Id = $id; Group = 'Other' }; UserAction = $null; ClientAppType = 'browser'; DevicePlatform = 'windows'; Country = 'US'; IpAddress = $null; LocationKey = 'home'; SignInRiskLevel = 'None'; UserRiskLevel = 'None' }
        $policy = New-Policy -Id 'p1' -Name 'MFA all' -Grant (New-Grant -Controls @('mfa'))
        $policy.conditions.applications.includeApplications = @($id)
        $outcome = Get-ResCaOutcome -Result @($policy)
        $text = Format-ResCaResult -Scenario $scenario -Outcome $outcome -Expectation ([pscustomobject]@{ Expect = 'Info'; Severity = 'Info'; Source = 'Default'; Note = '' }) -Verdict ([pscustomobject]@{ Status = 'Investigate'; Reason = 'r'; Severity = $null }) -Cache @{}
        $text | Should -Match 'Contoso HR \(11111111-2222-3333-4444-555555555555\)'
        $text | Should -Match '42 users; included by: MFA all; excluded by: Exempt'
        $text | Should -Match 'includes Contoso HR'
    }
    It 'lists the roles of a privileged persona and leaves the row out for other personas' {
        Mock Invoke-MtGraphRequest { @() }
        $app = [pscustomobject]@{ Key = 'exo'; Name = 'Office 365 Exchange Online'; Id = '00000002-0000-0ff1-ce00-000000000000'; Group = 'Other' }
        $make = { param($persona) [pscustomobject]@{ Persona = $persona; App = $app; UserAction = $null; ClientAppType = 'browser'; DevicePlatform = 'windows'; Country = 'US'; IpAddress = $null; LocationKey = 'home'; SignInRiskLevel = 'None'; UserRiskLevel = 'None' } }
        $outcome = Get-ResCaOutcome -Result @()
        $exp = [pscustomobject]@{ Expect = 'Info'; Severity = 'Info'; Source = 'Default'; Note = '' }
        $verdict = [pscustomobject]@{ Status = 'Investigate'; Reason = 'r'; Severity = $null }
        $admin = [pscustomobject]@{ Key = 'priv-01'; Kind = 'Privileged'; Label = 'Privileged:GlobalAdministrator'; UserId = 'a'; UserPrincipalName = 'a@c.com'; Roles = @('Global Administrator', 'User Administrator'); ClassSize = 1; ClassPolicies = @(); IsEmergencyAccess = $false }
        $member = [pscustomobject]@{ Key = 'member-c01'; Kind = 'Member'; Label = 'Member:class-1'; UserId = 'm'; UserPrincipalName = 'm@c.com'; ClassSize = 3; ClassPolicies = @(); IsEmergencyAccess = $false }
        (Format-ResCaResult -Scenario (& $make $admin) -Outcome $outcome -Expectation $exp -Verdict $verdict -Cache @{}) | Should -Match '\| Privileged roles \| Global Administrator, User Administrator \|'
        (Format-ResCaResult -Scenario (& $make $member) -Outcome $outcome -Expectation $exp -Verdict $verdict -Cache @{}) | Should -Not -Match 'Privileged roles'
    }
}
