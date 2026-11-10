# Unit tests of the shared helpers of the RESOURCIVE pack, with Graph and Exchange stubbed.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../powershell/Maester.psd1') -Force -ErrorAction Stop
    foreach ($file in (Get-ChildItem -Path (Join-Path $PSScriptRoot '../resourcive-pack/helpers') -Filter '*.ps1')) { . $file.FullName }
}

Describe 'ConvertTo-ResAssignmentSummary' {
    It 'reads all devices, all users, groups and none' {
        (ConvertTo-ResAssignmentSummary -Assignment @(@{ target = @{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' } })).Scope | Should -Be 'AllDevices'
        (ConvertTo-ResAssignmentSummary -Assignment @(@{ target = @{ '@odata.type' = '#microsoft.graph.allLicensedUsersAssignmentTarget' } })).Scope | Should -Be 'AllUsers'
        (ConvertTo-ResAssignmentSummary -Assignment @(@{ target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'g1' } })).Scope | Should -Be 'Groups'
        (ConvertTo-ResAssignmentSummary -Assignment @()).Scope | Should -Be 'None'
        (ConvertTo-ResAssignmentSummary -Assignment $null).Scope | Should -Be 'None'
    }
    It 'counts an exclusion group or a filter as an exclusion' {
        $a = ConvertTo-ResAssignmentSummary -Assignment @(
            @{ target = @{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' } },
            @{ target = @{ '@odata.type' = '#microsoft.graph.exclusionGroupAssignmentTarget'; groupId = 'g2' } })
        $a.Scope | Should -Be 'AllDevices'
        $a.HasExclusions | Should -BeTrue
        $b = ConvertTo-ResAssignmentSummary -Assignment @(@{ target = @{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget'; deviceAndAppManagementAssignmentFilterId = 'f1'; deviceAndAppManagementAssignmentFilterType = 'include' } })
        $b.HasExclusions | Should -BeTrue
    }
}

Describe 'Get-ResControlStatus' {
    BeforeAll {
        $script:all = [pscustomobject]@{ Scope = 'AllDevices'; HasExclusions = $false; Text = 'All devices' }
        $script:allEx = [pscustomobject]@{ Scope = 'AllDevices'; HasExclusions = $true; Text = 'All devices, 1 excluded group(s)' }
        $script:groups = [pscustomobject]@{ Scope = 'Groups'; HasExclusions = $false; Text = '1 group(s)' }
        $script:none = [pscustomobject]@{ Scope = 'None'; HasExclusions = $false; Text = 'Not assigned' }
    }
    It 'returns Not configured for no evidence' { (Get-ResControlStatus -Evidence @()).Status | Should -Be 'Not configured' }
    It 'returns Enforced for an enforcing policy for everyone' { (Get-ResControlStatus -Evidence @([pscustomobject]@{ Policy = 'p'; Mode = 'Enforced'; Assignment = $all })).Status | Should -Be 'Enforced' }
    It 'returns Partial scope for groups or exclusions' {
        (Get-ResControlStatus -Evidence @([pscustomobject]@{ Policy = 'p'; Mode = 'Enforced'; Assignment = $groups })).Status | Should -Be 'Partial scope'
        (Get-ResControlStatus -Evidence @([pscustomobject]@{ Policy = 'p'; Mode = 'Enforced'; Assignment = $allEx })).Status | Should -Be 'Partial scope'
    }
    It 'returns Audit-only and Not assigned' {
        (Get-ResControlStatus -Evidence @([pscustomobject]@{ Policy = 'p'; Mode = 'Audit'; Assignment = $all })).Status | Should -Be 'Audit-only'
        (Get-ResControlStatus -Evidence @([pscustomobject]@{ Policy = 'p'; Mode = 'Enforced'; Assignment = $none })).Status | Should -Be 'Not assigned'
    }
    It 'lets an enforcing all-devices policy win over a group policy' {
        $status = Get-ResControlStatus -Evidence @(
            [pscustomobject]@{ Policy = 'a'; Mode = 'Enforced'; Assignment = $groups },
            [pscustomobject]@{ Policy = 'b'; Mode = 'Enforced'; Assignment = $all })
        $status.Status | Should -Be 'Enforced'
    }
}

Describe 'ConvertTo-ResFlatSetting' {
    It 'walks choice children and group collections' {
        $instance = [pscustomobject]@{
            settingDefinitionId = 'Parent'
            choiceSettingValue  = [pscustomobject]@{ value = 'parent_1'; children = @(
                    [pscustomobject]@{ settingDefinitionId = 'Child'; simpleSettingValue = [pscustomobject]@{ value = '30' } },
                    [pscustomobject]@{ settingDefinitionId = 'Group'; groupSettingCollectionValue = @([pscustomobject]@{ children = @([pscustomobject]@{ settingDefinitionId = 'Leaf'; choiceSettingValue = [pscustomobject]@{ value = 'leaf_block'; children = @() } }) }) }) }
        }
        $flat = @(ConvertTo-ResFlatSetting -SettingInstance $instance)
        ($flat.DefinitionId) | Should -Be @('parent', 'child', 'group', 'leaf')
        ($flat | Where-Object DefinitionId -eq 'leaf').Value | Should -Be 'leaf_block'
        ($flat | Where-Object DefinitionId -eq 'child').Value | Should -Be '30'
    }
}

Describe 'Get-ResPolicyEvidence' {
    It 'maps values to modes with the patterns' {
        $policies = @(
            [pscustomobject]@{ Name = 'A'; Id = '1'; Assignment = 'x'; Settings = @([pscustomobject]@{ DefinitionId = 'rule_x'; Value = 'rule_x_block' }) },
            [pscustomobject]@{ Name = 'B'; Id = '2'; Assignment = 'x'; Settings = @([pscustomobject]@{ DefinitionId = 'rule_x'; Value = 'rule_x_audit' }) },
            [pscustomobject]@{ Name = 'C'; Id = '3'; Assignment = 'x'; Settings = @([pscustomobject]@{ DefinitionId = 'rule_x'; Value = 'rule_x_off' }) })
        $e = @(Get-ResPolicyEvidence -Policy $policies -DefinitionId 'rule_x' -EnforcedPattern '_block$' -AuditPattern '_(audit|warn)$')
        $e.Count | Should -Be 2
        ($e | Where-Object Policy -eq 'A').Mode | Should -Be 'Enforced'
        ($e | Where-Object Policy -eq 'B').Mode | Should -Be 'Audit'
    }
}

Describe 'Mail rule logic' {
    BeforeAll {
        $script:alice = [pscustomobject]@{ Addresses = @('alice@contoso.com'); Domain = 'contoso.com' }
        $script:bob = [pscustomobject]@{ Addresses = @('bob@fabrikam.com'); Domain = 'fabrikam.com' }
    }
    BeforeEach {
        Mock Resolve-ResGroupMemberAddress { param($Identity, $Cache) if ($Identity -eq 'execs') { , @('alice@contoso.com') } else { , @() } }
    }
    It 'normalises a rule and reads the kind from the name' {
        $rule = ConvertTo-ResMailRule -Rule ([pscustomobject]@{ Name = 'Strict Preset Security Policy'; State = 'Enabled'; SentTo = @('Alice@Contoso.com'); SentToMemberOf = $null })
        $rule.Kind | Should -Be 'Strict'
        $rule.SentTo | Should -Be @('alice@contoso.com')
        $rule.Enabled | Should -BeTrue
        (ConvertTo-ResMailRule -Rule ([pscustomobject]@{ Name = 'x'; State = 'Disabled' })).Enabled | Should -BeFalse
    }
    It 'applies a rule with no condition to everyone and not when disabled' {
        $rule = ConvertTo-ResMailRule -Rule ([pscustomobject]@{ Name = 'x'; State = 'Enabled' })
        Test-ResMailRuleApplies -Rule $rule -Recipient $alice -Cache @{} | Should -BeTrue
        $off = ConvertTo-ResMailRule -Rule ([pscustomobject]@{ Name = 'x'; State = 'Disabled' })
        Test-ResMailRuleApplies -Rule $off -Recipient $alice -Cache @{} | Should -BeFalse
    }
    It 'uses OR within a condition and AND across condition types' {
        $domainOrUser = ConvertTo-ResMailRule -Rule ([pscustomobject]@{ Name = 'x'; State = 'Enabled'; RecipientDomainIs = @('contoso.com', 'fabrikam.com') })
        Test-ResMailRuleApplies -Rule $domainOrUser -Recipient $alice -Cache @{} | Should -BeTrue
        Test-ResMailRuleApplies -Rule $domainOrUser -Recipient $bob -Cache @{} | Should -BeTrue
        $both = ConvertTo-ResMailRule -Rule ([pscustomobject]@{ Name = 'x'; State = 'Enabled'; RecipientDomainIs = @('contoso.com'); SentToMemberOf = @('execs') })
        Test-ResMailRuleApplies -Rule $both -Recipient $alice -Cache @{} | Should -BeTrue
        $bobContoso = [pscustomobject]@{ Addresses = @('bob@contoso.com'); Domain = 'contoso.com' }
        Test-ResMailRuleApplies -Rule $both -Recipient $bobContoso -Cache @{} | Should -BeFalse
    }
    It 'lets any exception remove the recipient, and the built-in rule has exceptions only' {
        $builtIn = ConvertTo-ResMailRule -Kind BuiltIn -Rule ([pscustomobject]@{ Name = 'ATP Built-In Protection Rule'; ExceptIfRecipientDomainIs = @('fabrikam.com') })
        Test-ResMailRuleApplies -Rule $builtIn -Recipient $alice -Cache @{} | Should -BeTrue
        Test-ResMailRuleApplies -Rule $builtIn -Recipient $bob -Cache @{} | Should -BeFalse
        $groupExcept = ConvertTo-ResMailRule -Kind BuiltIn -Rule ([pscustomobject]@{ Name = 'b'; ExceptIfSentToMemberOf = @('execs') })
        Test-ResMailRuleApplies -Rule $groupExcept -Recipient $alice -Cache @{} | Should -BeFalse
    }
}

Describe 'Licence and error helpers' {
    BeforeEach {
        Mock Add-MtTestResultDetail { throw "skip: $SkippedCustomReason" }
    }
    It 'Test-ResLicense reports true, false and unknown' {
        Mock Get-ResLicensedServicePlan { , @('AAD_PREMIUM', 'INTUNE_A') }
        Test-ResLicense -ServicePlan 'AAD_PREMIUM_P2' | Should -BeFalse
        Test-ResLicense -ServicePlan 'INTUNE_A', 'X' | Should -BeTrue
        Mock Get-ResLicensedServicePlan { $null }
        Test-ResLicense -ServicePlan 'INTUNE_A' | Should -BeNullOrEmpty
    }
    It 'Assert-ResLicense skips with a Not licensed reason only when the licence is known to be missing' {
        Mock Test-ResLicense { $false }
        { Assert-ResLicense -Name 'Entra ID P2' -ServicePlan 'AAD_PREMIUM_P2' } | Should -Throw 'skip: Not licensed:*'
        Mock Test-ResLicense { $null }
        { Assert-ResLicense -Name 'Entra ID P2' -ServicePlan 'AAD_PREMIUM_P2' } | Should -Not -Throw
        Mock Test-ResLicense { $true }
        { Assert-ResLicense -Name 'Entra ID P2' -ServicePlan 'AAD_PREMIUM_P2' } | Should -Not -Throw
    }
    It 'Resolve-ResGraphError maps licence and authorization errors to skips and rethrows the rest' {
        $licence = [System.Management.Automation.ErrorRecord]::new([System.Exception]::new('Neither tenant is B2C or tenant doesn''t have premium license'), 'x', 'NotSpecified', $null)
        { Resolve-ResGraphError -ErrorRecord $licence -Feature 'sign-ins' } | Should -Throw 'skip: Not licensed:*'
        $denied = [System.Management.Automation.ErrorRecord]::new([System.Exception]::new('Forbidden'), 'x', 'NotSpecified', $null)
        { Resolve-ResGraphError -ErrorRecord $denied -Feature 'sign-ins' -Requires 'AuditLog.Read.All' } | Should -Throw 'skip: Not authorized:*AuditLog.Read.All*'
        $other = [System.Management.Automation.ErrorRecord]::new([System.Exception]::new('boom'), 'x', 'NotSpecified', $null)
        { Resolve-ResGraphError -ErrorRecord $other -Feature 'sign-ins' } | Should -Throw 'boom'
    }
    It 'Get-ResLicensedServicePlan reads enabled SKUs only' {
        Mock Invoke-MtGraphRequest { @(
                [pscustomobject]@{ capabilityStatus = 'Enabled'; servicePlans = @([pscustomobject]@{ servicePlanName = 'INTUNE_A'; provisioningStatus = 'Success' }, [pscustomobject]@{ servicePlanName = 'OFF'; provisioningStatus = 'Disabled' }) },
                [pscustomobject]@{ capabilityStatus = 'Suspended'; servicePlans = @([pscustomobject]@{ servicePlanName = 'SUSPENDED'; provisioningStatus = 'Success' }) }) }
        $plans = Get-ResLicensedServicePlan
        $plans | Should -Contain 'INTUNE_A'
        $plans | Should -Not -Contain 'OFF'
        $plans | Should -Not -Contain 'SUSPENDED'
        Mock Invoke-MtGraphRequest { throw 'no access' }
        Get-ResLicensedServicePlan | Should -BeNullOrEmpty
    }
}

Describe 'Get-ResPrivilegedServicePrincipal' {
    It 'returns applications with roles, owner, secrets and flags, and skips users and non-privileged roles' {
        Mock Get-MgContext { [pscustomobject]@{ TenantId = 'mine' } }
        Mock Invoke-MtGraphRequest {
            switch -Wildcard ($RelativeUri) {
                'roleManagement/directory/roleDefinitions' { @([pscustomobject]@{ id = 'r1'; displayName = 'Global Administrator'; isPrivileged = $true }, [pscustomobject]@{ id = 'r2'; displayName = 'Reader'; isPrivileged = $false }) }
                'roleManagement/directory/roleAssignments' {
                    @([pscustomobject]@{ roleDefinitionId = 'r1'; principal = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.servicePrincipal'; id = 's1'; displayName = 'Backup Tool' } },
                        [pscustomobject]@{ roleDefinitionId = 'r1'; principal = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = 'u1' } },
                        [pscustomobject]@{ roleDefinitionId = 'r2'; principal = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.servicePrincipal'; id = 's2'; displayName = 'Reader App' } })
                }
                'roleManagement/directory/roleEligibilityScheduleInstances' { throw 'RequestFromNonPremiumTenantOrB2CTenant' }
                'servicePrincipals/s1' { [pscustomobject]@{ id = 's1'; displayName = 'Backup Tool'; appId = 'a1'; servicePrincipalType = 'Application'; appOwnerOrganizationId = 'other'; accountEnabled = $true; passwordCredentials = @([pscustomobject]@{ keyId = 'k' }); keyCredentials = @() } }
            }
        }
        $apps = @(Get-ResPrivilegedServicePrincipal)
        $apps.Count | Should -Be 1
        $apps[0].DisplayName | Should -Be 'Backup Tool'
        $apps[0].IsThirdParty | Should -BeTrue
        $apps[0].SecretCount | Should -Be 1
        $apps[0].Roles | Should -Be @('Global Administrator')
        $apps[0].EligibleReadable | Should -BeFalse
    }
    It 'treats an application of this tenant or of Microsoft as first-party' {
        Mock Get-MgContext { [pscustomobject]@{ TenantId = 'mine' } }
        Mock Invoke-MtGraphRequest {
            switch -Wildcard ($RelativeUri) {
                'roleManagement/directory/roleDefinitions' { @([pscustomobject]@{ id = 'r1'; displayName = 'Global Administrator'; isPrivileged = $true }) }
                'roleManagement/directory/roleAssignments' { @([pscustomobject]@{ roleDefinitionId = 'r1'; principal = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.servicePrincipal'; id = 's1' } }) }
                'servicePrincipals/s1' { [pscustomobject]@{ id = 's1'; displayName = 'Own App'; servicePrincipalType = 'ManagedIdentity'; appOwnerOrganizationId = 'mine'; accountEnabled = $true; passwordCredentials = @(); keyCredentials = @() } }
            }
        }
        $apps = @(Get-ResPrivilegedServicePrincipal -ActiveOnly)
        $apps[0].IsThirdParty | Should -BeFalse
        $apps[0].Type | Should -Be 'ManagedIdentity'
    }
}

Describe 'Get-ResPrivilegedUser' {
    It 'returns active and eligible users, expands groups and skips non-privileged roles' {
        Mock Invoke-MtGraphRequest {
            switch -Wildcard ($RelativeUri) {
                'roleManagement/directory/roleDefinitions' { @([pscustomobject]@{ id = 'r1'; displayName = 'Global Administrator'; isPrivileged = $true }, [pscustomobject]@{ id = 'r2'; displayName = 'Reader'; isPrivileged = $false }) }
                'roleManagement/directory/roleAssignments' {
                    @([pscustomobject]@{ roleDefinitionId = 'r1'; principal = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = 'u1'; userPrincipalName = 'a@c.com'; mail = 'a@c.com'; displayName = 'A'; accountEnabled = $true; userType = 'Member' } },
                        [pscustomobject]@{ roleDefinitionId = 'r2'; principal = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = 'u9'; userPrincipalName = 'z@c.com' } },
                        [pscustomobject]@{ roleDefinitionId = 'r1'; principal = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.group'; id = 'g1' } })
                }
                'roleManagement/directory/roleEligibilityScheduleInstances' { throw 'RequestFromNonPremiumTenantOrB2CTenant' }
                'groups/g1/transitiveMembers/*' { @([pscustomobject]@{ id = 'u2'; userPrincipalName = 'b@c.com'; mail = 'b@c.com'; displayName = 'B'; accountEnabled = $true; userType = 'Member' }) }
            }
        }
        $users = @(Get-ResPrivilegedUser)
        ($users.UserPrincipalName | Sort-Object) | Should -Be @('a@c.com', 'b@c.com')
        $users[0].EligibleReadable | Should -BeFalse
        $users[0].Roles | Should -Contain 'Global Administrator'
        (@(Get-ResPrivilegedUser -ActiveOnly)[0]).EligibleReadable | Should -BeTrue
    }

    Context 'a role-holding group that answers 404' {
        BeforeEach {
            $script:untyped = $true
            Mock Invoke-MtGraphRequest {
                switch -Wildcard ($RelativeUri) {
                    'roleManagement/directory/roleDefinitions' { @([pscustomobject]@{ id = 'r1'; displayName = 'Global Administrator'; isPrivileged = $true }) }
                    'roleManagement/directory/roleAssignments' {
                        @([pscustomobject]@{ roleDefinitionId = 'r1'; principal = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = 'u1'; userPrincipalName = 'a@c.com' } },
                            [pscustomobject]@{ roleDefinitionId = 'r1'; principal = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.group'; id = 'g1' } })
                    }
                    'groups/g1/transitiveMembers/*' { throw 'Response status code does not indicate success: NotFound (Not Found).' }
                    'groups/g1/transitiveMembers' {
                        if ($script:untyped) { @([pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = 'u2'; userPrincipalName = 'b@c.com' }, [pscustomobject]@{ '@odata.type' = '#microsoft.graph.group'; id = 'g2' }) }
                        else { throw 'Response status code does not indicate success: NotFound (Not Found).' }
                    }
                }
            }
        }
        It 'falls back to the untyped member list and keeps the users' {
            $users = @(Get-ResPrivilegedUser -ActiveOnly)
            ($users.UserPrincipalName | Sort-Object) | Should -Be @('a@c.com', 'b@c.com')
            @($users[0].UnreadableGroups).Count | Should -Be 0
        }
        It 'reports the group instead of failing when it cannot be read at all' {
            $script:untyped = $false
            $users = @(Get-ResPrivilegedUser -ActiveOnly -WarningVariable w -WarningAction SilentlyContinue)
            $users.UserPrincipalName | Should -Be @('a@c.com')
            $users[0].UnreadableGroups[0] | Should -BeLike 'g1 (*NotFound*'
            ($w -join ' ') | Should -BeLike '*g1*'
            (Get-ResPrivilegedUserNote -User $users) | Should -BeLike '*could not be read*g1*'
        }
    }

    Context 'a deleted role-holding group' {
        It 'recognises a deleted group that still holds a role assignment' {
            $script:untyped = $false
            Mock Invoke-MtGraphRequest {
                switch -Wildcard ($RelativeUri) {
                    'roleManagement/directory/roleDefinitions' { @([pscustomobject]@{ id = 'r1'; displayName = 'Global Administrator'; isPrivileged = $true }) }
                    'roleManagement/directory/roleAssignments' { @([pscustomobject]@{ roleDefinitionId = 'r1'; principal = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.group'; id = 'g1' } }, [pscustomobject]@{ roleDefinitionId = 'r1'; principal = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = 'u1'; userPrincipalName = 'a@c.com' } }) }
                    'groups/g1/transitiveMembers*' { throw 'Response status code does not indicate success: NotFound (Not Found).' }
                    'directory/deletedItems/microsoft.graph.group/g1' { [pscustomobject]@{ id = 'g1'; deletedDateTime = '2026-10-01T00:00:00Z' } }
                }
            }
            $users = @(Get-ResPrivilegedUser -ActiveOnly -WarningAction SilentlyContinue)
            $users[0].UnreadableGroups[0] | Should -BeLike 'g1 (a deleted group that still holds the role assignment*'
        }
    }

    Context 'Get-ResGraphPage' {
        It 'unwraps a raw response, reports more rows and accepts hashtables and plain rows' {
            $page = Get-ResGraphPage ([pscustomobject]@{ value = @([pscustomobject]@{ id = 1 }, [pscustomobject]@{ id = 2 }); '@odata.nextLink' = 'next' })
            @($page.Rows).Count | Should -Be 2
            $page.HasMore | Should -BeTrue
            $map = Get-ResGraphPage @{ value = @(@{ id = 1 }); '@odata.context' = 'c' }
            @($map.Rows).Count | Should -Be 1
            $map.HasMore | Should -BeFalse
            @((Get-ResGraphPage ([pscustomobject]@{ id = 7 })).Rows)[0].id | Should -Be 7
            @((Get-ResGraphPage $null).Rows).Count | Should -Be 0
            @((Get-ResGraphPage ([pscustomobject]@{ value = @() })).Rows).Count | Should -Be 0
        }
    }

    Context 'Get-ResPrivilegedUser role definitions' {
        It 'reads role definitions from the beta endpoint, which is the only one that returns isPrivileged' {
            Mock Invoke-MtGraphRequest { @() }
            Get-ResPrivilegedUser | Out-Null
            Should -Invoke Invoke-MtGraphRequest -ParameterFilter { $RelativeUri -eq 'roleManagement/directory/roleDefinitions' -and $ApiVersion -eq 'beta' } -Times 1 -Exactly
            Should -Invoke Invoke-MtGraphRequest -ParameterFilter { $RelativeUri -eq 'roleManagement/directory/roleDefinitions' -and $ApiVersion -eq 'v1.0' } -Times 0 -Exactly
        }
    }

}
