# Runs the endpoint checks of the RESOURCIVE pack with Graph stubbed, to check their pass, fail, investigate and skip paths.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../powershell/Maester.psd1') -Force -ErrorAction Stop
    foreach ($file in (Get-ChildItem -Path (Join-Path $PSScriptRoot '../resourcive-pack/helpers') -Filter '*.ps1')) { . $file.FullName }
    foreach ($file in (Get-ChildItem -Path (Join-Path $PSScriptRoot '../resourcive-pack/endpoint') -Filter 'Test.*.ps1')) { . $file.FullName }

    function New-Assignment { param([string] $Scope = 'AllDevices', [bool] $Exclusions = $false) [pscustomobject]@{ Scope = $Scope; HasExclusions = $Exclusions; Text = $Scope } }
    function S { param([string] $Id, [string] $Value) [pscustomobject]@{ DefinitionId = $Id; Value = $Value; Depth = 0 } }
    function New-Policy {
        param([string] $Name = 'P', [object[]] $Settings, $Assignment = (New-Assignment), [string] $Family = '')
        [pscustomobject]@{ Id = [guid]::NewGuid().ToString(); Name = $Name; TemplateFamily = $Family; Assignment = $Assignment; Settings = @($Settings) }
    }
    $script:asr = 'device_vendor_msft_policy_config_defender_attacksurfacereductionrules_'
}

Describe 'Endpoint checks' {
    BeforeEach {
        $script:detail = @()
        Mock Assert-ResLicense { }
        Mock Add-MtTestResultDetail {
            $script:detail += [pscustomobject]@{ Result = $Result; Investigate = [bool]$Investigate; Skipped = $SkippedBecause; Reason = $SkippedCustomReason }
            if ($SkippedBecause) { throw "skipped:$SkippedBecause" }
        }
    }

    Context 'MP.RESOURCIVE.1001 Entra LAPS' {
        It 'passes when enabled and fails when not' {
            Mock Invoke-MtGraphRequest { [pscustomobject]@{ localAdminPassword = [pscustomobject]@{ isEnabled = $true } } }
            Test-ResEntraLapsEnabled | Should -BeTrue
            Mock Invoke-MtGraphRequest { [pscustomobject]@{ localAdminPassword = [pscustomobject]@{ isEnabled = $false } } }
            Test-ResEntraLapsEnabled | Should -BeFalse
        }
    }

    Context 'MP.RESOURCIVE.1002 Intune LAPS' {
        It 'passes for an all-devices policy that rotates within the limit' {
            Mock Get-ResIntuneConfigurationPolicy { New-Policy -Settings @((S 'device_vendor_msft_laps_policies_backupdirectory' 'device_vendor_msft_laps_policies_backupdirectory_1'), (S 'device_vendor_msft_laps_policies_passwordagedays' '30')) }
            Test-ResIntuneLapsAssigned | Should -BeTrue
        }
        It 'fails when the password age is too long' {
            Mock Get-ResIntuneConfigurationPolicy { New-Policy -Settings @((S 'device_vendor_msft_laps_policies_backupdirectory' 'x_1'), (S 'device_vendor_msft_laps_policies_passwordagedays' '90')) }
            Test-ResIntuneLapsAssigned | Should -BeFalse
        }
        It 'is Investigate when only a group is assigned' {
            Mock Get-ResIntuneConfigurationPolicy { New-Policy -Assignment (New-Assignment -Scope Groups) -Settings @((S 'device_vendor_msft_laps_policies_backupdirectory' 'x_1')) }
            Test-ResIntuneLapsAssigned | Should -BeFalse
            $detail[-1].Investigate | Should -BeTrue
        }
        It 'fails with no policy' {
            Mock Get-ResIntuneConfigurationPolicy { }
            Test-ResIntuneLapsAssigned | Should -BeFalse
            $detail[-1].Investigate | Should -BeFalse
        }
    }

    Context 'MP.RESOURCIVE.1003 USB' {
        BeforeEach { Mock Get-ResIntuneLegacyProfile { } }
        It 'passes with the storage CSP deny write for all devices' {
            Mock Get-ResIntuneConfigurationPolicy { New-Policy -Settings @((S 'device_vendor_msft_policy_config_storage_removablediskdenywriteaccess' 'device_vendor_msft_policy_config_storage_removablediskdenywriteaccess_1')) }
            Test-ResUsbStorageBlocked | Should -BeTrue
        }
        It 'fails when only write is blocked and read block is required' {
            Mock Get-ResIntuneConfigurationPolicy { New-Policy -Settings @((S 'device_vendor_msft_policy_config_storage_removablediskdenywriteaccess' 'x_1')) }
            Test-ResUsbStorageBlocked -RequireReadBlock | Should -BeFalse
        }
        It 'passes on default deny enforcement' {
            Mock Get-ResIntuneConfigurationPolicy { New-Policy -Settings @((S 'device_vendor_msft_defender_configuration_defaultenforcement' 'device_vendor_msft_defender_configuration_defaultenforcement_2')) }
            Test-ResUsbStorageBlocked -RequireReadBlock | Should -BeTrue
        }
        It 'does not count the ASR USB rule as blocking storage' {
            Mock Get-ResIntuneConfigurationPolicy { New-Policy -Settings @((S "${asr}blockuntrustedunsignedprocessesthatrunfromusb" "${asr}blockuntrustedunsignedprocessesthatrunfromusb_block")) }
            Test-ResUsbStorageBlocked | Should -BeFalse
            $detail[-1].Result | Should -Match 'Related control, not counted'
        }
        It 'is Investigate for a group-scoped policy' {
            Mock Get-ResIntuneConfigurationPolicy { New-Policy -Assignment (New-Assignment -Scope Groups) -Settings @((S 'device_vendor_msft_policy_config_storage_removablediskdenywriteaccess' 'x_1')) }
            Test-ResUsbStorageBlocked | Should -BeFalse
            $detail[-1].Investigate | Should -BeTrue
        }
        It 'reads the device restrictions template, custom OMA-URI and Administrative Templates' {
            Mock Get-ResIntuneConfigurationPolicy { }
            Mock Get-ResIntuneLegacyProfile { [pscustomobject]@{ Name = 'Restrictions'; Kind = 'DeviceRestrictions'; Properties = [pscustomobject]@{ storageBlockRemovableStorage = $true }; OmaSettings = @(); AdmxDefinitions = @(); Assignment = (New-Assignment) } }
            Test-ResUsbStorageBlocked | Should -BeTrue
            Mock Get-ResIntuneLegacyProfile { [pscustomobject]@{ Name = 'Custom'; Kind = 'Custom'; Properties = $null; OmaSettings = @([pscustomobject]@{ OmaUri = './Device/Vendor/MSFT/Policy/Config/Storage/RemovableDiskDenyWriteAccess'; Value = '1' }); AdmxDefinitions = @(); Assignment = (New-Assignment) } }
            Test-ResUsbStorageBlocked | Should -BeTrue
            Mock Get-ResIntuneLegacyProfile { [pscustomobject]@{ Name = 'ADMX'; Kind = 'AdministrativeTemplates'; Properties = $null; OmaSettings = @(); AdmxDefinitions = @([pscustomobject]@{ DisplayName = 'Removable Disks: Deny write access'; CategoryPath = '\System\Removable Storage Access'; Enabled = $true }); Assignment = (New-Assignment) } }
            Test-ResUsbStorageBlocked | Should -BeTrue
        }
    }

    Context 'MP.RESOURCIVE.1004 scripts and 1005 ASR' {
        BeforeAll {
            function New-AsrPolicy { param([string[]] $Block = @(), [string[]] $Audit = @(), $Assignment = (New-Assignment))
                $settings = @(); foreach ($k in $Block) { $settings += , (S "$asr$k" "$asr${k}_block") }; foreach ($k in $Audit) { $settings += , (S "$asr$k" "$asr${k}_audit") }
                New-Policy -Name 'ASR' -Settings $settings -Assignment $Assignment }
        }
        It '1004 passes when both script rules block for all devices' {
            Mock Get-ResIntuneConfigurationPolicy { New-AsrPolicy -Block @('blockexecutionofpotentiallyobfuscatedscripts', 'blockjavascriptorvbscriptfromlaunchingdownloadedexecutablecontent') }
            Test-ResUntrustedScriptsBlocked | Should -BeTrue
        }
        It '1004 fails when a script rule only audits and no App Control enforces' {
            Mock Get-ResIntuneConfigurationPolicy { New-AsrPolicy -Block @('blockexecutionofpotentiallyobfuscatedscripts') -Audit @('blockjavascriptorvbscriptfromlaunchingdownloadedexecutablecontent') }
            Test-ResUntrustedScriptsBlocked | Should -BeFalse
            $detail[-1].Result | Should -Match 'Constrained Language Mode'
        }
        It '1004 passes with an enforcing App Control policy and fails when it is in audit mode' {
            $enforcing = New-Policy -Name 'AppControl' -Family 'endpointSecurityApplicationControl' -Settings @((S 'device_vendor_msft_policy_config_applicationcontrolv2_buildoptions' 'x_built_in_controls_selected'))
            $audit = New-Policy -Name 'AppControl' -Family 'endpointSecurityApplicationControl' -Settings @((S 'device_vendor_msft_policy_config_applicationcontrolv2_auditmode' 'device_vendor_msft_policy_config_applicationcontrolv2_auditmode_enabled'))
            Mock Get-ResIntuneConfigurationPolicy { $enforcing }
            Test-ResUntrustedScriptsBlocked | Should -BeTrue
            Mock Get-ResIntuneConfigurationPolicy { $audit }
            Test-ResUntrustedScriptsBlocked | Should -BeFalse
        }
        It '1005 passes only when every rule blocks, is Investigate for partial scope and fails otherwise' {
            $all = (Get-ResAsrRule).Key
            Mock Get-ResIntuneConfigurationPolicy { New-AsrPolicy -Block $all }
            Test-ResAsrRulesBlocking | Should -BeTrue
            Mock Get-ResIntuneConfigurationPolicy { New-AsrPolicy -Block $all -Assignment (New-Assignment -Scope Groups) }
            Test-ResAsrRulesBlocking | Should -BeFalse
            $detail[-1].Investigate | Should -BeTrue
            Mock Get-ResIntuneConfigurationPolicy { New-AsrPolicy -Block ($all | Select-Object -Skip 1) }
            Test-ResAsrRulesBlocking | Should -BeFalse
            $detail[-1].Investigate | Should -BeFalse
            Test-ResAsrRulesBlocking -RulesNotRequired (Get-ResAsrRule | Select-Object -First 1).Name | Should -BeTrue
        }
        It '1005 does not require the server-only or preview rules and reports an Off rule as Disabled' {
            $required = (Get-ResAsrRule | Where-Object { $_.Applicability -eq 'Required' }).Key
            (Get-ResAsrRule | Where-Object { $_.Applicability -ne 'Required' }).Key | Should -Contain 'blockwebshellcreationforservers'
            Mock Get-ResIntuneConfigurationPolicy { New-AsrPolicy -Block $required }
            Test-ResAsrRulesBlocking | Should -BeTrue
            $detail[-1].Result | Should -Match 'Windows Server only'
            Mock Get-ResIntuneConfigurationPolicy { New-Policy -Name 'ASR' -Settings @((S "${asr}blockexecutionofpotentiallyobfuscatedscripts" "${asr}blockexecutionofpotentiallyobfuscatedscripts_off")) }
            Test-ResAsrRulesBlocking | Should -BeFalse
            $detail[-1].Result | Should -Match 'Disabled'
        }
    }

    Context 'MP.RESOURCIVE.1006 Defender AV policy' {
        It 'passes when every protection is enforced and fails when one is missing' {
            $p = 'device_vendor_msft_policy_config_defender_'
            $full = New-Policy -Settings @((S "${p}allowrealtimemonitoring" "${p}allowrealtimemonitoring_1"), (S "${p}allowbehaviormonitoring" "${p}allowbehaviormonitoring_1"),
                (S "${p}allowcloudprotection" "${p}allowcloudprotection_1"), (S "${p}allowioavprotection" "${p}allowioavprotection_1"),
                (S "${p}enablenetworkprotection" "${p}enablenetworkprotection_1"), (S "${p}puaprotection" "${p}puaprotection_1"))
            Mock Get-ResIntuneConfigurationPolicy { $full }
            Test-ResDefenderAntivirusBaseline | Should -BeTrue
            Mock Get-ResIntuneConfigurationPolicy { New-Policy -Settings @((S "${p}allowrealtimemonitoring" "${p}allowrealtimemonitoring_1")) }
            Test-ResDefenderAntivirusBaseline | Should -BeFalse
        }
        It 'does not count network protection in audit mode as enforced' {
            $p = 'device_vendor_msft_policy_config_defender_'
            Mock Get-ResIntuneConfigurationPolicy { New-Policy -Settings @((S "${p}enablenetworkprotection" "${p}enablenetworkprotection_2")) }
            Test-ResDefenderAntivirusBaseline | Should -BeFalse
            $detail[-1].Result | Should -Match 'Network protection \(block mode\) \| Audit-only'
        }
    }

    Context 'MP.RESOURCIVE.1007 Defender device state' {
        It 'passes, fails and skips' {
            $good = [pscustomobject]@{ deviceName = 'D1'; userPrincipalName = 'u'; windowsProtectionState = [pscustomobject]@{ realTimeProtectionEnabled = $true; tamperProtectionEnabled = $true; signatureUpdateOverdue = $false; malwareProtectionEnabled = $true } }
            $bad = [pscustomobject]@{ deviceName = 'D2'; userPrincipalName = 'v'; windowsProtectionState = [pscustomobject]@{ realTimeProtectionEnabled = $false; tamperProtectionEnabled = $true; signatureUpdateOverdue = $false; malwareProtectionEnabled = $true } }
            Mock Invoke-MtGraphRequest { @($good) }
            Test-ResDefenderDeviceProtectionState | Should -BeTrue
            Mock Invoke-MtGraphRequest { @($good, $bad) }
            Test-ResDefenderDeviceProtectionState | Should -BeFalse
            Test-ResDefenderDeviceProtectionState -AllowedFailingPercent 50 | Should -BeTrue
            Mock Invoke-MtGraphRequest { @() }
            { Test-ResDefenderDeviceProtectionState } | Should -Throw 'skipped:NotApplicable'
        }
        It 'does not treat devices without a state as passing' {
            Mock Invoke-MtGraphRequest { if ($RelativeUri -like 'deviceManagement/managedDevices/*/windowsProtectionState') { $null } else { @([pscustomobject]@{ id = '1'; deviceName = 'D3' }) } }
            Test-ResDefenderDeviceProtectionState | Should -BeFalse
            $detail[-1].Investigate | Should -BeTrue
        }
    }

    Context 'MP.RESOURCIVE.1008 and 1009 BitLocker' {
        BeforeAll { $script:bl = 'device_vendor_msft_bitlocker_requiredeviceencryption' }
        It '1008 passes with a policy for all devices and encrypted devices' {
            Mock Get-ResIntuneConfigurationPolicy { New-Policy -Settings @((S $bl "${bl}_1")) }
            Mock Get-ResWindowsManagedDevice { @([pscustomobject]@{ deviceName = 'D'; isEncrypted = $true }) }
            Test-ResBitLockerEnforcedAndEncrypted | Should -BeTrue
        }
        It '1008 fails for an unencrypted device and honours the percentage' {
            Mock Get-ResIntuneConfigurationPolicy { New-Policy -Settings @((S $bl "${bl}_1")) }
            Mock Get-ResWindowsManagedDevice { @([pscustomobject]@{ deviceName = 'D'; isEncrypted = $true }, [pscustomobject]@{ deviceName = 'E'; isEncrypted = $false }) }
            Test-ResBitLockerEnforcedAndEncrypted | Should -BeFalse
            Test-ResBitLockerEnforcedAndEncrypted -MinimumEncryptedPercent 50 | Should -BeTrue
        }
        It '1008 and 1009 leave devices that have not synced for a long time out of the totals' {
            $old = (Get-Date).ToUniversalTime().AddDays(-120).ToString('o'); $now = (Get-Date).ToUniversalTime().ToString('o')
            $d1 = '11111111-1111-1111-1111-111111111111'; $d2 = '22222222-2222-2222-2222-222222222222'
            Mock Get-ResIntuneConfigurationPolicy { New-Policy -Settings @((S $bl "${bl}_1")) }
            Mock Get-ResWindowsManagedDevice { @([pscustomobject]@{ deviceName = 'live'; isEncrypted = $true; azureADDeviceId = $d1; lastSyncDateTime = $now }, [pscustomobject]@{ deviceName = 'ghost'; isEncrypted = $false; azureADDeviceId = $d2; lastSyncDateTime = $old }) }
            Test-ResBitLockerEnforcedAndEncrypted | Should -BeTrue
            $detail[-1].Result | Should -Match '1 device\(s\) have not synced'
            Mock Get-ResWindowsManagedDevice { @([pscustomobject]@{ deviceName = 'live'; isEncrypted = $true; azureADDeviceId = $d1; lastSyncDateTime = $now }, [pscustomobject]@{ deviceName = 'ghost'; isEncrypted = $true; azureADDeviceId = $d2; lastSyncDateTime = $old }) }
            Mock Invoke-MtGraphRequest { @([pscustomobject]@{ id = 'k'; deviceId = $d1 }) }
            Test-ResBitLockerRecoveryKeyEscrow | Should -BeTrue
        }
        It '1009 matches recovery keys to encrypted devices' {
            $d1 = '11111111-1111-1111-1111-111111111111'; $d2 = '22222222-2222-2222-2222-222222222222'
            Mock Get-ResWindowsManagedDevice { @([pscustomobject]@{ deviceName = 'D1'; isEncrypted = $true; azureADDeviceId = $d1 }, [pscustomobject]@{ deviceName = 'D2'; isEncrypted = $true; azureADDeviceId = $d2 }) }
            Mock Invoke-MtGraphRequest { @([pscustomobject]@{ id = 'k'; deviceId = $d1 }) }
            Test-ResBitLockerRecoveryKeyEscrow | Should -BeFalse
            $detail[-1].Result | Should -Match 'D2'
            Mock Invoke-MtGraphRequest { @([pscustomobject]@{ id = 'k'; deviceId = $d1 }, [pscustomobject]@{ id = 'k2'; deviceId = $d2.ToUpper() }) }
            Test-ResBitLockerRecoveryKeyEscrow | Should -BeTrue
        }
    }

    Context 'MP.RESOURCIVE.1010 compliance' {
        BeforeAll {
            function New-Compliance { param($Name = 'C', $Scope = 'AllDevices', [string[]] $On = @(), $Grace = 0)
                [pscustomobject]@{ '@odata.type' = '#microsoft.graph.windows10CompliancePolicy'; id = $Name; displayName = $Name
                    bitLockerEnabled = ($On -contains 'bitLockerEnabled'); defenderEnabled = ($On -contains 'defenderEnabled'); rtpEnabled = ($On -contains 'rtpEnabled'); activeFirewallRequired = ($On -contains 'activeFirewallRequired')
                    assignments = @(if ($Scope -eq 'AllDevices') { @{ target = @{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' } } } elseif ($Scope -eq 'Groups') { @{ target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'g' } } })
                    scheduledActionsForRule = @([pscustomobject]@{ scheduledActionConfigurations = @([pscustomobject]@{ actionType = 'block'; gracePeriodHours = $Grace * 24 }) }) } }
        }
        BeforeEach {
            # The policy list is read with one expand; each policy's actions are expanded on the policy itself (a sub-path 400s).
            $script:comp = @()
            Mock Invoke-MtGraphRequest {
                if ($QueryParameters -and $QueryParameters['$expand'] -like 'scheduledActionsForRule*') { $id = ($RelativeUri -split '/')[2]; $script:comp | Where-Object { $_.id -eq $id } }
                else { @($script:comp | Select-Object -Property * -ExcludeProperty scheduledActionsForRule) }
            }
        }
        It 'never sends a nested expand' {
            $script:comp = @(New-Compliance -On @('bitLockerEnabled') -Grace 1)
            Test-ResWindowsCompliancePolicyCoverage | Out-Null
            Should -Invoke Invoke-MtGraphRequest -ParameterFilter { $RelativeUri -match '\(\$expand' } -Times 0 -Exactly
            Should -Invoke Invoke-MtGraphRequest -ParameterFilter { $RelativeUri -notlike '*scheduledActionsForRule*' -and $QueryParameters -and $QueryParameters['$expand'] -eq 'scheduledActionsForRule($expand=scheduledActionConfigurations)' } -Times 1 -Exactly
        }
        It 'passes when policies for all devices require the settings and block' {
            $script:comp = @(New-Compliance -On @('bitLockerEnabled', 'defenderEnabled', 'rtpEnabled', 'activeFirewallRequired') -Grace 3)
            Test-ResWindowsCompliancePolicyCoverage | Should -BeTrue
        }
        It 'combines settings across policies and fails on a missing one or a long grace period' {
            $script:comp = @((New-Compliance -Name 'a' -On @('bitLockerEnabled', 'defenderEnabled') -Grace 1), (New-Compliance -Name 'b' -On @('rtpEnabled', 'activeFirewallRequired') -Grace 1))
            Test-ResWindowsCompliancePolicyCoverage | Should -BeTrue
            $script:comp = @(New-Compliance -On @('bitLockerEnabled') -Grace 1)
            Test-ResWindowsCompliancePolicyCoverage | Should -BeFalse
            $script:comp = @(New-Compliance -On @('bitLockerEnabled', 'defenderEnabled', 'rtpEnabled', 'activeFirewallRequired') -Grace 30)
            Test-ResWindowsCompliancePolicyCoverage | Should -BeFalse
        }
        It 'is Investigate when only a group completes the requirement' {
            $script:comp = @(New-Compliance -Scope Groups -On @('bitLockerEnabled', 'defenderEnabled', 'rtpEnabled', 'activeFirewallRequired') -Grace 1)
            Test-ResWindowsCompliancePolicyCoverage | Should -BeFalse
            $detail[-1].Investigate | Should -BeTrue
        }
        It 'fails when there is no Windows policy' {
            $script:comp = @()
            Test-ResWindowsCompliancePolicyCoverage | Should -BeFalse
        }
    }

    Context 'MP.RESOURCIVE.1011 CA compliant device' {
        BeforeAll {
            function New-CaPolicy { param($State = 'enabled', $Users = @('All'), $Apps = @('All'), $Controls = @('compliantDevice'), $Operator = 'OR')
                [pscustomobject]@{ displayName = 'CA'; state = $State; grantControls = [pscustomobject]@{ builtInControls = $Controls; operator = $Operator }
                    conditions = [pscustomobject]@{ users = [pscustomobject]@{ includeUsers = $Users; excludeUsers = @(); excludeGroups = @(); excludeRoles = @() }; applications = [pscustomobject]@{ includeApplications = $Apps }; platforms = $null } } }
        }
        It 'passes for an enabled all-users all-apps policy' {
            Mock Get-MtConditionalAccessPolicy { New-CaPolicy }
            Test-ResCaRequiresCompliantDevice | Should -BeTrue
        }
        It 'is Investigate for report-only and for a scoped policy, and an OR with MFA does not count as required' {
            Mock Get-MtConditionalAccessPolicy { New-CaPolicy -State enabledForReportingButNotEnforced }
            Test-ResCaRequiresCompliantDevice | Should -BeFalse
            $detail[-1].Investigate | Should -BeTrue
            Mock Get-MtConditionalAccessPolicy { New-CaPolicy -Users @('some-user') }
            Test-ResCaRequiresCompliantDevice | Should -BeFalse
            Mock Get-MtConditionalAccessPolicy { New-CaPolicy -Controls @('compliantDevice', 'mfa') -Operator 'OR' }
            Test-ResCaRequiresCompliantDevice | Should -BeFalse
            Mock Get-MtConditionalAccessPolicy { New-CaPolicy -Controls @('compliantDevice', 'mfa') -Operator 'AND' }
            Test-ResCaRequiresCompliantDevice | Should -BeTrue
        }
        It 'fails when nothing requires a device' {
            Mock Get-MtConditionalAccessPolicy { New-CaPolicy -Controls @('mfa') }
            Test-ResCaRequiresCompliantDevice | Should -BeFalse
            $detail[-1].Investigate | Should -BeFalse
        }
    }

    Context 'MP.RESOURCIVE.1012 unmanaged joined devices' {
        It 'flags recently active unmanaged joined devices and ignores registered ones by default' {
            $recent = (Get-Date).ToUniversalTime().AddDays(-2).ToString('o'); $old = (Get-Date).ToUniversalTime().AddDays(-90).ToString('o')
            Mock Invoke-MtGraphRequest { @(
                    [pscustomobject]@{ displayName = 'managed'; operatingSystem = 'Windows'; trustType = 'AzureAd'; isManaged = $true; approximateLastSignInDateTime = $recent; accountEnabled = $true },
                    [pscustomobject]@{ displayName = 'byod'; operatingSystem = 'iOS'; trustType = 'Workplace'; isManaged = $false; approximateLastSignInDateTime = $recent; accountEnabled = $true },
                    [pscustomobject]@{ displayName = 'stale'; operatingSystem = 'Windows'; trustType = 'AzureAd'; isManaged = $false; approximateLastSignInDateTime = $old; accountEnabled = $true }) }
            Test-ResUnmanagedJoinedDevices | Should -BeTrue
            Test-ResUnmanagedJoinedDevices -IncludeRegistered | Should -BeFalse
            Mock Invoke-MtGraphRequest { @([pscustomobject]@{ displayName = 'rogue'; operatingSystem = 'Windows'; trustType = 'AzureAd'; isManaged = $false; approximateLastSignInDateTime = $recent; accountEnabled = $true }) }
            Test-ResUnmanagedJoinedDevices | Should -BeFalse
            Test-ResUnmanagedJoinedDevices -ExcludedOperatingSystems Windows | Should -BeTrue
        }
        It 'leaves out printers and computer accounts and reports hybrid devices separately' {
            $recent = (Get-Date).ToUniversalTime().AddDays(-2).ToString('o')
            Mock Invoke-MtGraphRequest { @(
                    [pscustomobject]@{ displayName = 'HP-Printer'; operatingSystem = 'Printer'; trustType = 'AzureAd'; isManaged = $false; approximateLastSignInDateTime = $recent; accountEnabled = $true },
                    [pscustomobject]@{ displayName = 'SRV01$'; operatingSystem = 'Windows'; trustType = 'ServerAd'; isManaged = $false; approximateLastSignInDateTime = $recent; accountEnabled = $true },
                    [pscustomobject]@{ displayName = 'hybrid-pc'; operatingSystem = 'Windows'; trustType = 'ServerAd'; isManaged = $false; approximateLastSignInDateTime = $recent; accountEnabled = $true }) }
            Test-ResUnmanagedJoinedDevices | Should -BeFalse
            $detail[-1].Investigate | Should -BeTrue
            $detail[-1].Result | Should -Match 'hybrid-pc'
            $detail[-1].Result | Should -Not -Match 'HP-Printer|SRV01'
        }
    }

    Context 'MP.RESOURCIVE.1013 device registration' {
        BeforeAll {
            function New-RegPolicy { param($Quota = 20, $Join = 'all', $Mfa = 'notRequired')
                [pscustomobject]@{ userDeviceQuota = $Quota; multiFactorAuthConfiguration = $Mfa; azureADJoin = [pscustomobject]@{ allowedToJoin = [pscustomobject]@{ '@odata.type' = "#microsoft.graph.$Join" } } } }
        }
        BeforeEach { Mock Test-ResLicense { $true }; Mock Get-MtConditionalAccessPolicy { @() } }
        It 'passes with a quota, and MFA in the policy' {
            Mock Invoke-MtGraphRequest { New-RegPolicy -Mfa 'required' -Join 'allDeviceRegistrationMembership' }
            Test-ResDeviceRegistrationControls | Should -BeTrue
        }
        It 'fails when anyone can join and nothing requires MFA, or when the quota is high' {
            Mock Invoke-MtGraphRequest { New-RegPolicy -Join 'allDeviceRegistrationMembership' }
            Test-ResDeviceRegistrationControls | Should -BeFalse
            Mock Invoke-MtGraphRequest { New-RegPolicy -Quota 50 -Join 'noDeviceRegistrationMembership' }
            Test-ResDeviceRegistrationControls | Should -BeFalse
        }
        It 'accepts a Conditional Access MFA policy for the register device user action' {
            Mock Invoke-MtGraphRequest { New-RegPolicy -Join 'allDeviceRegistrationMembership' }
            Mock Get-MtConditionalAccessPolicy { @([pscustomobject]@{ displayName = 'Reg MFA'; state = 'enabled'; conditions = [pscustomobject]@{ applications = [pscustomobject]@{ includeUserActions = @('urn:user:registerdevice') } }; grantControls = [pscustomobject]@{ builtInControls = @('mfa') } }) }
            Test-ResDeviceRegistrationControls | Should -BeTrue
        }
        It 'is Investigate when Conditional Access cannot be read and MFA is otherwise missing' {
            Mock Invoke-MtGraphRequest { New-RegPolicy -Join 'allDeviceRegistrationMembership' }
            Mock Test-ResLicense { $false }
            Test-ResDeviceRegistrationControls | Should -BeFalse
            $detail[-1].Investigate | Should -BeTrue
        }
    }
}
