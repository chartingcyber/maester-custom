# The privileged-user checks name their users on the Affected objects page and add facts about them.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../powershell/Maester.psd1') -Force -ErrorAction Stop
    foreach ($file in (Get-ChildItem -Path (Join-Path $PSScriptRoot '../resourcive-pack/helpers') -Filter '*.ps1')) { . $file.FullName }
    foreach ($folder in 'entra', 'mail', 'endpoint', 'conditional-access') {
        foreach ($file in (Get-ChildItem -Path (Join-Path $PSScriptRoot "../resourcive-pack/$folder") -Filter 'Test.*.ps1')) { . $file.FullName }
    }
}

Describe 'Affected objects for privileged users' {
    BeforeEach {
        $script:detail = @()
        $script:facts = @()
        Mock Assert-ResLicense { }
        Mock Add-MtTestResultDetail {
            $script:detail += [pscustomobject]@{ Result = $Result; GraphObjects = @($GraphObjects); GraphObjectType = $GraphObjectType }
            if ($SkippedBecause) { throw "skipped:$SkippedBecause" }
        }
        Mock Add-MtAffectedObjectFact { $script:facts += [pscustomobject]@{ Type = $Type; Id = $Id; Source = $Source; Fact = @($Fact) } }
        Mock Get-ResPrivilegedUser {
            @([pscustomobject]@{ Id = 'u1'; UserPrincipalName = 'weak@c.com'; DisplayName = 'Weak'; Roles = @('Global Administrator', 'User Administrator', 'Exchange Administrator'); AccountEnabled = $true; EligibleReadable = $true; UnreadableGroups = @() },
                [pscustomobject]@{ Id = 'u2'; UserPrincipalName = 'good@c.com'; DisplayName = 'Good'; Roles = @('Helpdesk Administrator'); AccountEnabled = $true; EligibleReadable = $true; UnreadableGroups = @() })
        }
        Mock Invoke-MtGraphRequest {
            @([pscustomobject]@{ id = 'u1'; isMfaRegistered = $true; isMfaCapable = $false; isPasswordlessCapable = $false; methodsRegistered = @('mobilePhone') },
                [pscustomobject]@{ id = 'u2'; isMfaRegistered = $true; isMfaCapable = $true; isPasswordlessCapable = $true; methodsRegistered = @('fido2') })
        }
    }

    It '3002 names only the user without a phishing-resistant method, with facts' {
        Test-ResPrivilegedPhishingResistantMethod | Should -BeFalse
        $detail[-1].GraphObjectType | Should -Be 'Users'
        @($detail[-1].GraphObjects.Id) | Should -Be @('u1')
        # Facts go to every assessed user, so one who passes shows it too; only the failing user is named.
        @($facts.Id | Sort-Object) | Should -Be @('u1', 'u2')
        $good = $facts | Where-Object { $_.Id -eq 'u2' }
        ($good.Fact | Where-Object Key -EQ 'resourcive.phishingResistant').Raw | Should -BeTrue
        ($good.Fact | Where-Object Key -EQ 'resourcive.phishingResistant').Tone | Should -Be 'Good'
        $facts = @($facts | Where-Object { $_.Id -eq 'u1' })
        $facts[0].Type | Should -Be 'User'
        $facts[0].Source | Should -Be 'Resourcive M365 Assessment'
        $byKey = @{}; foreach ($f in $facts[0].Fact) { if ($f.Key) { $byKey[$f.Key] = $f } }
        $byKey['resourcive.phishingResistant'].Raw | Should -BeFalse
        $byKey['resourcive.phishingResistant'].Tone | Should -Be 'Risk'
        $byKey['user.privilegedRoles'].Raw | Should -Be @('Global Administrator', 'User Administrator', 'Exchange Administrator')
        $byKey['user.mfaRegistered'].Raw | Should -BeTrue
    }

    It '3011 names the user that cannot complete MFA' {
        Test-ResPrivilegedMfaCapable | Should -BeFalse
        @($detail[-1].GraphObjects.Id) | Should -Be @('u1')
        @($facts.Id | Sort-Object) | Should -Be @('u1', 'u2')
        (($facts | Where-Object { $_.Id -eq 'u1' }).Fact | Where-Object { $_.Key -eq 'resourcive.mfaCapable' }).Raw | Should -BeFalse
        (($facts | Where-Object { $_.Id -eq 'u2' }).Fact | Where-Object { $_.Key -eq 'resourcive.mfaCapable' }).Raw | Should -BeTrue
    }

    It '3010 names every listed account and adds its roles' {
        Mock Get-ResPrivilegedServicePrincipal { @() }
        Test-ResPrivilegedRoleInventory | Should -BeTrue
        @($detail[-1].GraphObjects.Id) | Should -Be @('u1', 'u2')
        @($facts.Id | Sort-Object) | Should -Be @('u1', 'u2')
        ($facts | Where-Object Id -EQ 'u1').Fact | Where-Object Name -EQ 'Review marks' | ForEach-Object { $_.Value } | Should -Match '3 roles'
    }

    It '2002 names the user outside the Strict preset' {
        Mock Get-ResMailRecipient { @([pscustomobject]@{ DisplayName = 'weak@c.com'; UserPrincipalName = 'weak@c.com'; PrimarySmtpAddress = 'weak@c.com'; Domain = 'c.com'; Addresses = @('weak@c.com') }) }
        Mock Get-MtExo { }
        Test-ResPrivilegedUsersStrictPreset | Should -BeFalse
        @($detail[-1].GraphObjects.Id) | Should -Be @('u1')
        ($facts[0].Fact | Where-Object { $_.Key -eq 'resourcive.presetPolicy' }).Raw | Should -Be 'Neither'
    }

    It 'names nobody when every user passes' {
        Mock Invoke-MtGraphRequest { @([pscustomobject]@{ id = 'u1'; isMfaCapable = $true; isMfaRegistered = $true; methodsRegistered = @('fido2') }, [pscustomobject]@{ id = 'u2'; isMfaCapable = $true; isMfaRegistered = $true; methodsRegistered = @('fido2') }) }
        Test-ResPrivilegedMfaCapable | Should -BeTrue
        @($detail[-1].GraphObjects) | Should -BeNullOrEmpty
        @($facts | ForEach-Object { $_.Fact | Where-Object Name -EQ 'Multifactor authentication' | ForEach-Object { $_.Tone } } | Select-Object -Unique) | Should -Be @('Good')
    }

    It 'adds no fact for a user without an id' {
        Add-ResPrivilegedUserFact -User ([pscustomobject]@{ UserPrincipalName = 'x@c.com'; Roles = @() }) -Registration $null
        $facts.Count | Should -Be 0
    }

    It '3010 names applications with facts and adds last sign-in to users' {
        Mock Get-ResPrivilegedServicePrincipal { @([pscustomobject]@{ Id = 'sp1'; DisplayName = 'Backup tool'; Type = 'Application'; OwnerOrganizationId = 'other'; IsThirdParty = $true; AccountEnabled = $true; SecretCount = 2; CertificateCount = 0; Roles = @('Global Administrator'); ActiveRoles = @('Global Administrator'); EligibleRoles = @() }) }
        Mock Get-ResUserActivity { @{ u1 = [pscustomobject]@{ LastSignIn = [datetime]::UtcNow.AddDays(-200); LastPasswordChange = [datetime]::UtcNow.AddDays(-40); Created = $null } } }
        Test-ResPrivilegedRoleInventory | Should -BeTrue
        $types = @($detail[-1].GraphObjects | ForEach-Object { $_.'@odata.type' })
        $types | Should -Contain '#microsoft.graph.servicePrincipal'
        $types | Should -Contain '#microsoft.graph.user'
        $detail[-1].GraphObjectType | Should -BeNullOrEmpty
        $app = $facts | Where-Object { $_.Type -eq 'ServicePrincipal' }
        $app.Id | Should -Be 'sp1'
        ($app.Fact | Where-Object Key -EQ 'resourcive.secretCount').Raw | Should -Be 2
        ($app.Fact | Where-Object Key -EQ 'resourcive.thirdParty').Raw | Should -BeTrue
        $user = $facts | Where-Object { $_.Id -eq 'u1' }
        ($user.Fact | Where-Object Key -EQ 'signIn.daysSince').Raw | Should -Be 200
        ($user.Fact | Where-Object Key -EQ 'signIn.daysSince').Tone | Should -Be 'Warning'
        ($user.Fact | Where-Object Key -EQ 'resourcive.passwordAgeDays').Raw | Should -Be 40
    }

    It '1012 names unmanaged devices and adds the shared device facts' {
        $recent = (Get-Date).ToUniversalTime().AddDays(-3).ToString('o')
        Mock Invoke-MtGraphRequest { @([pscustomobject]@{ id = 'dev1'; displayName = 'LAPTOP1'; operatingSystem = 'Windows'; trustType = 'AzureAd'; isManaged = $false; isCompliant = $false; approximateLastSignInDateTime = $recent; accountEnabled = $true }) }
        Test-ResUnmanagedJoinedDevices | Should -BeFalse
        @($detail[-1].GraphObjects.id) | Should -Be @('dev1')
        $device = $facts | Where-Object { $_.Type -eq 'Device' }
        ($device.Fact | Where-Object Key -EQ 'device.managed').Raw | Should -BeFalse
        ($device.Fact | Where-Object Key -EQ 'device.joinType').Raw | Should -Be 'AzureAd'
        ($device.Fact | Where-Object Key -EQ 'device.os').Raw | Should -Be 'Windows'
        ($device.Fact | Where-Object Key -EQ 'signIn.daysSince').Raw | Should -Be 3
    }
}

Describe 'MP.RESOURCIVE.3012 privileged users excluded from Conditional Access' {
    BeforeEach {
        $script:detail = @()
        $script:facts = @()
        Mock Assert-ResLicense { }
        Mock Add-MtTestResultDetail {
            $script:detail += [pscustomobject]@{ Result = $Result; GraphObjects = @($GraphObjects); Investigate = [bool]$Investigate; Skipped = $SkippedBecause }
            if ($SkippedBecause) { throw "skipped:$SkippedBecause" }
        }
        Mock Add-MtAffectedObjectFact { $script:facts += [pscustomobject]@{ Type = $Type; Id = $Id; Fact = @($Fact) } }
        Mock Get-ResPrivilegedUser {
            @([pscustomobject]@{ Id = 'u1'; UserPrincipalName = 'excluded@c.com'; DisplayName = 'Excluded'; Roles = @('Global Administrator'); ActiveRoles = @('Global Administrator'); EligibleRoles = @(); AccountEnabled = $true; EligibleReadable = $true; UnreadableGroups = @() },
                [pscustomobject]@{ Id = 'u2'; UserPrincipalName = 'covered@c.com'; DisplayName = 'Covered'; Roles = @('User Administrator'); ActiveRoles = @('User Administrator'); EligibleRoles = @(); AccountEnabled = $true; EligibleReadable = $true; UnreadableGroups = @() })
        }
        Mock Get-ResCaUserRoleMap { @{} }
        Mock Get-ResCaGroupMemberId { @{ '__failed' = @() } }
        $script:policy = {
            param($Id, $Name, $State, $Exclude)
            [pscustomobject]@{ id = $Id; displayName = $Name; state = $State; modifiedDateTime = '2026-10-01T00:00:00Z'
                conditions = [pscustomobject]@{ users = [pscustomobject]@{ includeUsers = @('All'); excludeUsers = @($Exclude); includeGroups = @(); excludeGroups = @(); includeRoles = @(); excludeRoles = @() } }
                grantControls = [pscustomobject]@{ builtInControls = @('mfa') }; sessionControls = $null }
        }
    }

    It 'fails, names the excluded user and the policy, and counts the exclusion on the policy' {
        Mock Get-MtConditionalAccessPolicy { @((& $policy 'p1' 'Require MFA' 'enabled' @('u1')), (& $policy 'p2' 'Block legacy' 'enabled' @()), (& $policy 'p3' 'Report only' 'enabledForReportingButNotEnforced' @('u2'))) }
        Test-ResPrivilegedUserCaExclusion | Should -BeFalse
        $detail[-1].Result | Should -Match 'excluded@c.com'
        $detail[-1].Result | Should -Not -Match 'covered@c.com'
        @($detail[-1].GraphObjects.id | Sort-Object) | Should -Be @('p1', 'u1')
        ($facts | Where-Object { $_.Id -eq 'u1' }).Fact | Where-Object Key -EQ 'resourcive.caExcludedCount' | ForEach-Object { $_.Raw } | Should -Be 1
        $policyFact = ($facts | Where-Object { $_.Type -eq 'ConditionalAccessPolicy' }).Fact
        ($policyFact | Where-Object Key -EQ 'resourcive.privilegedExcluded').Raw | Should -Be 1
        ($policyFact | Where-Object Key -EQ 'resourcive.caState').Raw | Should -Be 'Enforced'
    }
    It 'is Investigate, not a failure, when only an emergency access account is excluded' {
        Mock Get-MtConditionalAccessPolicy { @((& $policy 'p1' 'Require MFA' 'enabled' @('u1'))) }
        Test-ResPrivilegedUserCaExclusion -EmergencyAccessAccounts @(@{ Id = 'u1' }) | Should -BeTrue
        $detail[-1].Investigate | Should -BeTrue
        $detail[-1].Result | Should -Match 'Only emergency access'
        (($facts | Where-Object { $_.Id -eq 'u1' }).Fact | Where-Object Key -EQ 'resourcive.emergencyAccess').Raw | Should -BeTrue
    }
    It 'passes when nobody is excluded, and skips with no enforced policy' {
        Mock Get-MtConditionalAccessPolicy { @((& $policy 'p2' 'Block legacy' 'enabled' @())) }
        Test-ResPrivilegedUserCaExclusion | Should -BeTrue
        @($detail[-1].GraphObjects) | Should -BeNullOrEmpty
        @($facts | ForEach-Object { $_.Fact | Where-Object Key -EQ 'resourcive.caExcludedCount' | ForEach-Object { $_.Raw } } | Select-Object -Unique) | Should -Be @(0)
        Mock Get-MtConditionalAccessPolicy { @((& $policy 'p3' 'Report only' 'enabledForReportingButNotEnforced' @('u1'))) }
        { Test-ResPrivilegedUserCaExclusion } | Should -Throw 'skipped:NotApplicable'
    }
}

Describe 'Add-ResCaScenarioFact' {
    BeforeEach {
        $script:facts = @()
        Mock Add-MtAffectedObjectFact { $script:facts += [pscustomobject]@{ Type = $Type; Id = $Id; Fact = @($Fact) } }
        $script:scenario = [pscustomobject]@{
            Persona = [pscustomobject]@{ Key = 'member-c01'; UserId = 'u9'; UserPrincipalName = 'rep@c.com'; DisplayName = 'Rep'; ClassSize = 40; ClassPolicies = @('Require MFA (Excluded)', 'Block legacy (Included)') }
            UserAction = $null; App = [pscustomobject]@{ Name = 'Office 365' }; LocationKey = 'us'; ClientAppType = 'exchangeActiveSync'; DevicePlatform = 'windows'
        }
        $script:verdict = [pscustomobject]@{ Status = 'Fail'; Reason = 'Observed NoControl, expected Block.' }
        $script:policies = @([pscustomobject]@{ id = 'p1'; displayName = 'Require MFA'; state = 'enabled'; conditions = [pscustomobject]@{ users = [pscustomobject]@{ includeUsers = @('All'); excludeUsers = @() } }; grantControls = [pscustomobject]@{ builtInControls = @('mfa') } })
    }
    It 'says the persona stands for its class, counts failures, and counts them on the excluding policy' {
        $cache = [hashtable]::Synchronized(@{})
        $null = Add-ResCaScenarioFact -Scenario $scenario -Verdict $verdict -Policy $policies -Cache $cache
        $objects = @(Add-ResCaScenarioFact -Scenario $scenario -Verdict $verdict -Policy $policies -Cache $cache)
        $user = @($facts | Where-Object { $_.Type -eq 'User' })[-1]
        ($user.Fact | Where-Object Key -EQ 'resourcive.personaClassSize').Raw | Should -Be 40
        ($user.Fact | Where-Object Key -EQ 'resourcive.caFailingScenarios').Raw | Should -Be 2
        ($user.Fact | Where-Object Name -EQ 'Failing sign-in scenarios').Value | Should -Match 'whole class'
        $policy = @($facts | Where-Object { $_.Type -eq 'ConditionalAccessPolicy' })[-1]
        ($policy.Fact | Where-Object Key -EQ 'resourcive.caExcludedFailures').Raw | Should -Be 2
        @($objects | ForEach-Object { $_.'@odata.type' } | Sort-Object) | Should -Be @('#microsoft.graph.conditionalAccessPolicy', '#microsoft.graph.user')
    }
    It 'counts a scenario that only needs review separately from a failure' {
        $cache = [hashtable]::Synchronized(@{})
        $null = Add-ResCaScenarioFact -Scenario $scenario -Verdict ([pscustomobject]@{ Status = 'Investigate'; Reason = 'Informational.' }) -Policy $policies -Cache $cache
        $user = @($facts | Where-Object { $_.Type -eq 'User' })[-1]
        ($user.Fact | Where-Object Key -EQ 'resourcive.caReviewScenarios').Raw | Should -Be 1
        $user.Fact | Where-Object Key -EQ 'resourcive.caFailingScenarios' | Should -BeNullOrEmpty
    }
    It 'does not name the user when names are redacted, but still names the policy' {
        $objects = @(Add-ResCaScenarioFact -Scenario $scenario -Verdict $verdict -Policy $policies -Cache ([hashtable]::Synchronized(@{})) -Redact)
        @($facts | Where-Object { $_.Type -eq 'User' }).Count | Should -Be 0
        @($objects | ForEach-Object { $_.'@odata.type' }) | Should -Be @('#microsoft.graph.conditionalAccessPolicy')
    }
}
