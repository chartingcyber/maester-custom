# Runs the identity checks of the RESOURCIVE pack with Graph stubbed.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../powershell/Maester.psd1') -Force -ErrorAction Stop
    foreach ($file in (Get-ChildItem -Path (Join-Path $PSScriptRoot '../resourcive-pack/helpers') -Filter '*.ps1')) { . $file.FullName }
    foreach ($file in (Get-ChildItem -Path (Join-Path $PSScriptRoot '../resourcive-pack/entra') -Filter 'Test.*.ps1')) { . $file.FullName }
}

Describe 'Entra checks' {
    BeforeEach {
        $script:detail = @()
        Mock Assert-ResLicense { }
        Mock Add-MtTestResultDetail {
            $script:detail += [pscustomobject]@{ Result = $Result; Investigate = [bool]$Investigate; Skipped = $SkippedBecause; Reason = $SkippedCustomReason }
            if ($SkippedBecause) { throw "skipped:$SkippedBecause" }
        }
    }

    Context 'MP.RESOURCIVE.3010 privileged role inventory' {
        It 'lists accounts and roles, marks risky ones and is Investigate' {
            Mock Get-ResPrivilegedUser {
                @([pscustomobject]@{ UserPrincipalName = 'ga@contoso.com'; UserType = 'Member'; AccountEnabled = $true; OnPremisesSyncEnabled = $false; Roles = @('Global Administrator'); ActiveRoles = @('Global Administrator'); EligibleRoles = @(); EligibleReadable = $true; UnreadableGroups = @() },
                    [pscustomobject]@{ UserPrincipalName = 'ext@fabrikam.com'; UserType = 'Guest'; AccountEnabled = $true; OnPremisesSyncEnabled = $false; Roles = @('User Administrator', 'Exchange Administrator', 'Helpdesk Administrator'); ActiveRoles = @('User Administrator'); EligibleRoles = @('Exchange Administrator', 'Helpdesk Administrator'); EligibleReadable = $true; UnreadableGroups = @() })
            }
            Test-ResPrivilegedRoleInventory | Should -BeTrue
            $detail[-1].Investigate | Should -BeTrue
            $detail[-1].Result | Should -Match '2 account\(s\) hold a privileged role'
            $detail[-1].Result | Should -Match 'ext@fabrikam.com \| Guest \| Yes \| Cloud \| User Administrator \| Exchange Administrator, Helpdesk Administrator \| Guest; 3 roles'
            $detail[-1].Result | Should -Match '\| Global Administrator \| 1 \| 1 \| 0 \|'
        }
        It 'passes plainly when nobody holds a role' {
            Mock Get-ResPrivilegedUser { }
            Test-ResPrivilegedRoleInventory | Should -BeTrue
            $detail[-1].Investigate | Should -BeFalse
        }
    }

    Context 'MP.RESOURCIVE.3001 change log' {
        It 'is Investigate with changes and passes without' {
            Mock Invoke-MtGraphRequest { @() }
            Test-ResSecurityChangeLog | Should -BeTrue
            $detail[-1].Investigate | Should -BeFalse
            Mock Invoke-MtGraphRequest { @([pscustomobject]@{ activityDateTime = '2026-10-20T10:00:00Z'; activityDisplayName = 'Update conditional access policy'; category = 'Policy'; initiatedBy = [pscustomobject]@{ user = [pscustomobject]@{ userPrincipalName = 'admin@contoso.com' } }; targetResources = @([pscustomobject]@{ displayName = 'Block legacy' }) }) }
            Test-ResSecurityChangeLog | Should -BeTrue
            $detail[-1].Investigate | Should -BeTrue
            $detail[-1].Result | Should -Match 'admin@contoso.com'
        }
    }

    Context 'MP.RESOURCIVE.3001 own changes' {
        It 'marks changes made by the signed-in account and keeps them listed' {
            Mock Get-MgContext { [pscustomobject]@{ Account = 'me@contoso.com' } }
            Mock Invoke-MtGraphRequest { @(
                    [pscustomobject]@{ activityDateTime = (Get-Date).ToUniversalTime().AddHours(-1).ToString('o'); activityDisplayName = 'Consent to application'; category = 'ApplicationManagement'; initiatedBy = [pscustomobject]@{ user = [pscustomobject]@{ userPrincipalName = 'me@contoso.com' } }; targetResources = @([pscustomobject]@{ displayName = 'Microsoft Graph Command Line Tools' }) },
                    [pscustomobject]@{ activityDateTime = (Get-Date).ToUniversalTime().AddDays(-10).ToString('o'); activityDisplayName = 'Add delegated permission grant'; category = 'ApplicationManagement'; initiatedBy = [pscustomobject]@{ user = [pscustomobject]@{ userPrincipalName = 'me@contoso.com' } }; targetResources = @([pscustomobject]@{ displayName = 'Old grant' }) },
                    [pscustomobject]@{ activityDateTime = '2026-10-19T10:00:00Z'; activityDisplayName = 'Update conditional access policy'; category = 'Policy'; initiatedBy = [pscustomobject]@{ user = [pscustomobject]@{ userPrincipalName = 'other@contoso.com' } }; targetResources = @() }) }
            Test-ResSecurityChangeLog | Should -BeTrue
            $detail[-1].Investigate | Should -BeTrue
            $detail[-1].Result | Should -Match 'me@contoso.com \*'
            $detail[-1].Result | Should -Not -Match 'other@contoso.com \*'
            $detail[-1].Result | Should -Match 'Made by the account that ran this assessment'
            $detail[-1].Result | Should -Match 'Old grant \|'
            ([regex]::Matches($detail[-1].Result, 'me@contoso.com \*')).Count | Should -Be 1
            $detail[-1].Result | Should -Match 'Update conditional access policy'
        }
    }

    Context 'MP.RESOURCIVE.3002 phishing-resistant methods' {
        BeforeEach { Mock Get-ResPrivilegedUser { @([pscustomobject]@{ Id = 'u1'; UserPrincipalName = 'a@c.com'; Roles = @('Global Administrator'); AccountEnabled = $true; EligibleReadable = $true }) } }
        It 'passes with a passkey and fails with SMS only' {
            Mock Invoke-MtGraphRequest { @([pscustomobject]@{ id = 'u1'; methodsRegistered = @('microsoftAuthenticatorPush', 'passKeyDeviceBound') }) }
            Test-ResPrivilegedPhishingResistantMethod | Should -BeTrue
            Mock Invoke-MtGraphRequest { @([pscustomobject]@{ id = 'u1'; methodsRegistered = @('mobilePhone') }) }
            Test-ResPrivilegedPhishingResistantMethod | Should -BeFalse
            $detail[-1].Result | Should -Match 'Only phone'
            Mock Invoke-MtGraphRequest { @([pscustomobject]@{ id = 'u1'; methodsRegistered = $null }) }
            Test-ResPrivilegedPhishingResistantMethod | Should -BeFalse
            $detail[-1].Result | Should -Match 'No method registered'
        }
        It 'is Investigate for a privileged user with no registration record' {
            Mock Invoke-MtGraphRequest { @() }
            Test-ResPrivilegedPhishingResistantMethod | Should -BeFalse
            $detail[-1].Investigate | Should -BeTrue
        }
        It 'skips with no privileged users' {
            Mock Get-ResPrivilegedUser { }
            Mock Invoke-MtGraphRequest { @() }
            { Test-ResPrivilegedPhishingResistantMethod } | Should -Throw 'skipped:NotApplicable'
        }
    }

    Context 'MP.RESOURCIVE.3003 cross-tenant trust' {
        It 'fails when the default trusts MFA claims and passes when nothing is trusted' {
            Mock Invoke-MtGraphRequest { if ($RelativeUri -like '*default') { [pscustomobject]@{ inboundTrust = [pscustomobject]@{ isMfaAccepted = $true } } } else { @() } }
            Test-ResCrossTenantInboundTrust | Should -BeFalse
            $detail[-1].Result | Should -Match 'MFA claims'
            Mock Invoke-MtGraphRequest { if ($RelativeUri -like '*default') { [pscustomobject]@{ inboundTrust = [pscustomobject]@{ isMfaAccepted = $false; isCompliantDeviceAccepted = $false; isHybridAzureADJoinedDeviceAccepted = $false } } } else { @([pscustomobject]@{ tenantId = 'partner-1'; inboundTrust = [pscustomobject]@{ isMfaAccepted = $true } }) } }
            Test-ResCrossTenantInboundTrust | Should -BeTrue
            $detail[-1].Result | Should -Match 'partner-1'
        }
    }

    Context 'MP.RESOURCIVE.3004 GDAP' {
        It 'skips with a reason when no relationships are readable and no export is given' {
            Mock Invoke-MtGraphRequest { throw 'Forbidden' }
            { Test-ResDelegatedAdminRelationships } | Should -Throw 'skipped:Custom'
            $detail[-1].Reason | Should -Match 'partner'
        }
        It 'evaluates a partner export' {
            $file = Join-Path ([System.IO.Path]::GetTempPath()) "gdap-$([guid]::NewGuid()).json"
            $end = (Get-Date).ToUniversalTime().AddDays(400).ToString('o')
            @(@{ displayName = 'MSP admin'; status = 'active'; endDateTime = $end; customer = @{ displayName = 'Contoso' }; accessDetails = @{ unifiedRoles = @(@{ roleDefinitionId = '62e90394-69f5-4237-9190-012177145e10' }) } },
                @{ displayName = 'MSP helpdesk'; status = 'active'; endDateTime = $end; accessDetails = @{ unifiedRoles = @(@{ roleDefinitionId = 'f2ef992c-3afb-46b9-b7cf-a126ee74c451' }) } }) | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $file
            try {
                Mock Invoke-MtGraphRequest { throw 'Forbidden' }
                Test-ResDelegatedAdminRelationships -PartnerExportPath $file | Should -BeFalse
                $detail[-1].Result | Should -Match 'MSP admin'
                $detail[-1].Result | Should -Not -Match 'MSP helpdesk \|'
            } finally { Remove-Item -LiteralPath $file -Force }
        }
        It 'skips when the export file does not exist' {
            Mock Invoke-MtGraphRequest { throw 'Forbidden' }
            { Test-ResDelegatedAdminRelationships -PartnerExportPath '/nonexistent/gdap.json' } | Should -Throw 'skipped:Custom'
        }
    }

    Context 'sign-in checks on advanced hunting (Find-ResSignInHunting, 3005, 3009)' {
        BeforeAll {
            function New-HuntRow { param($Country = 'RU', $User = 'a@c.com', $App = 'Browser', $Logon = '["interactiveUser"]') [pscustomobject]@{ Timestamp = '2026-11-08T10:00:00Z'; AccountUpn = $User; Country = $Country; City = 'X'; Application = 'Office'; ClientAppUsed = $App; LogonType = $Logon; IPAddress = '203.0.113.9' } }
            # The first query counts sign-ins (summarize), the second returns the matches.
            function Set-Hunt { param($Rows = @(), $Total = 500) $script:huntRows = @($Rows); $script:huntTotal = $Total }
        }
        BeforeEach {
            Mock Test-ResLicense { $true }
            Set-Hunt
            Mock Invoke-MtGraphSecurityQuery { if ($Query -match 'summarize') { @([pscustomobject]@{ Total = $script:huntTotal; Oldest = '2026-11-02T00:00:00Z' }) } else { $script:huntRows } }
        }

        Context 'Find-ResSignInHunting' {
            It 'counts the sign-ins first, then asks for the matches only, newest first, limited to ten' {
                Set-Hunt -Rows @((New-HuntRow 'RU'), (New-HuntRow 'CN' 'b@c.com')) -Total 321
                $r = Find-ResSignInHunting -Kind Country -ExpectedCountry US, ca
                $r.Total | Should -Be 321
                @($r.Matches).Count | Should -Be 2
                $r.AtLeast | Should -BeFalse
                $r.Matches[0].location.countryOrRegion | Should -Be 'RU'
                $r.Matches[0].userPrincipalName | Should -Be 'a@c.com'
                Should -Invoke Invoke-MtGraphSecurityQuery -Times 1 -Exactly -ParameterFilter { $Query -match 'summarize Total = count\(\)' -and $Timespan -eq 'P7D' }
                Should -Invoke Invoke-MtGraphSecurityQuery -Times 1 -Exactly -ParameterFilter {
                    $Query -match 'EntraIdSignInEvents' -and $Query -match 'ErrorCode == 0' -and $Query -match 'Country !in~ \("US", "CA"\)' -and $Query -match 'order by Timestamp desc' -and $Query -match 'take 10$'
                }
            }
            It 'says at least when the limit is reached' {
                Set-Hunt -Rows @(1..10 | ForEach-Object { New-HuntRow 'RU' "u$_@c.com" })
                (Find-ResSignInHunting -Kind Country -ExpectedCountry US).AtLeast | Should -BeTrue
            }
            It 'builds the legacy filter from the client app' {
                Set-Hunt -Rows @((New-HuntRow -App 'IMAP4' -Logon '["nonInteractiveUser"]'))
                $r = Find-ResSignInHunting -Kind Legacy -LookbackDays 3 -MaximumMatches 5
                $r.Matches[0].clientAppUsed | Should -Be 'IMAP4'
                $r.Matches[0].logonType | Should -Match 'nonInteractiveUser'
                Should -Invoke Invoke-MtGraphSecurityQuery -ParameterFilter { $Query -match 'ClientAppUsed !in~ \("Browser", "Mobile Apps and Desktop clients", "Unknown"\)' -and $Query -match 'ago\(3d\)' -and $Query -match 'take 5$' -and $Timespan -eq 'P3D' }
            }
            It 'rejects anything that is not a two-letter country code' {
                { Find-ResSignInHunting -Kind Country -ExpectedCountry 'US"; drop' } | Should -Throw
            }
            It 'throws when the query cannot run so the caller can explain' {
                Mock Invoke-MtGraphSecurityQuery { throw 'Failed to resolve table or column expression named EntraIdSignInEvents' }
                { Find-ResSignInHunting -Kind Country -ExpectedCountry US } | Should -Throw '*EntraIdSignInEvents*'
            }
        }

        Context '3005 sign-in countries' {
            It 'defaults to US and CA, fails on a sign-in from another country and lists it' {
                Set-Hunt -Rows @((New-HuntRow 'RU' 'b@c.com'))
                Test-ResSignInsFromUnexpectedCountries | Should -BeFalse
                $detail[-1].Investigate | Should -BeFalse
                $detail[-1].Result | Should -Match 'b@c.com'
                $detail[-1].Result | Should -Match 'outside US, CA'
                $detail[-1].Result | Should -Match 'ExpectedCountries'
                $detail[-1].Result | Should -Match 'iso.org'
                Should -Invoke Invoke-MtGraphSecurityQuery -ParameterFilter { $Query -match 'Country !in~ \("US", "CA"\)' }
            }
            It 'passes when nothing is outside the expected countries, and says how many sign-ins it searched' {
                Set-Hunt -Rows @() -Total 812
                Test-ResSignInsFromUnexpectedCountries | Should -BeTrue
                $detail[-1].Result | Should -Match 'Well done'
                $detail[-1].Result | Should -Match 'Searched 812'
            }
            It 'uses the countries it is given instead of the default' {
                Set-Hunt -Rows @()
                Test-ResSignInsFromUnexpectedCountries -ExpectedCountries 'gb', 'IE' | Should -BeTrue
                Should -Invoke Invoke-MtGraphSecurityQuery -ParameterFilter { $Query -match 'Country !in~ \("GB", "IE"\)' -and $Query -notmatch '"US"' }
                $detail[-1].Result | Should -Match 'outside GB, IE'
            }
            It 'rejects a country that is not a two-letter code' {
                { Test-ResSignInsFromUnexpectedCountries -ExpectedCountries 'USA' } | Should -Throw
            }
            It 'is Investigate with the reason, why and manual steps when the tenant has no Entra ID P2, and runs no query' {
                Mock Test-ResLicense { $false }
                Mock Invoke-MtGraphSecurityQuery { throw 'must not be called' }
                Test-ResSignInsFromUnexpectedCountries | Should -BeFalse
                $detail[-1].Investigate | Should -BeTrue
                $detail[-1].Result | Should -Match 'does not have Microsoft Entra ID P2'
                $detail[-1].Result | Should -Match 'Why this is a manual check'
                $detail[-1].Result | Should -Match 'How to check by hand'
                $detail[-1].Result | Should -Match 'Sign-in logs'
                $detail[-1].Result | Should -Match 'Location'
                $detail[-1].Result | Should -Match 'non-interactive'
                $detail[-1].Result | Should -Match 'US, CA'
                $detail[-1].Result | Should -Not -Match 'Well done'
                Should -Invoke Invoke-MtGraphSecurityQuery -Times 0 -Exactly
            }
            It 'is Investigate, not a pass or an error, when the hunting query fails' {
                Mock Invoke-MtGraphSecurityQuery { throw 'Forbidden: insufficient privileges' }
                Test-ResSignInsFromUnexpectedCountries | Should -BeFalse
                $detail[-1].Investigate | Should -BeTrue
                $detail[-1].Result | Should -Match 'could not run'
                $detail[-1].Result | Should -Match 'Forbidden'
                $detail[-1].Result | Should -Match 'How to check by hand'
            }
            It 'is Investigate when the table holds no sign-ins at all, so an empty table is not a pass' {
                Set-Hunt -Rows @() -Total 0
                Test-ResSignInsFromUnexpectedCountries | Should -BeFalse
                $detail[-1].Investigate | Should -BeTrue
                $detail[-1].Result | Should -Match 'returned no successful sign-ins'
            }
            It 'still runs the query when the licences cannot be read' {
                Mock Test-ResLicense { $null }
                Set-Hunt -Rows @()
                Test-ResSignInsFromUnexpectedCountries | Should -BeTrue
            }
        }

        Context '3009 legacy sign-ins' {
            It 'fails on a legacy sign-in and lists user, protocol and logon type' {
                Set-Hunt -Rows @((New-HuntRow -User 'm@c.com' -App 'IMAP4' -Logon '["nonInteractiveUser"]'))
                Test-ResLegacyAuthenticationSignIns | Should -BeFalse
                $detail[-1].Investigate | Should -BeFalse
                $detail[-1].Result | Should -Match 'm@c.com'
                $detail[-1].Result | Should -Match 'IMAP4'
                $detail[-1].Result | Should -Match 'nonInteractiveUser'
            }
            It 'passes when none is found in a table that holds sign-ins' {
                Set-Hunt -Rows @() -Total 640
                Test-ResLegacyAuthenticationSignIns | Should -BeTrue
                $detail[-1].Result | Should -Match 'Searched 640'
            }
            It 'is Investigate with the reason, why and manual steps when the tenant has no Entra ID P2' {
                Mock Test-ResLicense { $false }
                Mock Invoke-MtGraphSecurityQuery { throw 'must not be called' }
                Test-ResLegacyAuthenticationSignIns | Should -BeFalse
                $detail[-1].Investigate | Should -BeTrue
                $detail[-1].Result | Should -Match 'does not have Microsoft Entra ID P2'
                $detail[-1].Result | Should -Match 'Why this is a manual check'
                $detail[-1].Result | Should -Match 'Client app'
                $detail[-1].Result | Should -Match 'non-interactive'
                $detail[-1].Result | Should -Not -Match 'Well done'
                Should -Invoke Invoke-MtGraphSecurityQuery -Times 0 -Exactly
            }
            It 'is Investigate when the hunting query fails or the table is empty' {
                Mock Invoke-MtGraphSecurityQuery { throw 'Failed to resolve table EntraIdSignInEvents' }
                Test-ResLegacyAuthenticationSignIns | Should -BeFalse
                $detail[-1].Investigate | Should -BeTrue
                $detail[-1].Result | Should -Match 'could not run'
                Set-Hunt -Rows @() -Total 0
                Test-ResLegacyAuthenticationSignIns | Should -BeFalse
                $detail[-1].Investigate | Should -BeTrue
            }
        }
    }

    Context 'MP.RESOURCIVE.3006 HIBP' {
        BeforeEach {
            $script:savedKey = $env:RESOURCIVE_HIBP_API_KEY
            Mock Get-ResPrivilegedUser { @([pscustomobject]@{ UserPrincipalName = 'admin@contoso.com'; Mail = 'admin@contoso.com' }) }
            Mock Invoke-MtGraphRequest { @([pscustomobject]@{ id = 'contoso.com'; isVerified = $true }, [pscustomobject]@{ id = 'contoso.onmicrosoft.com'; isVerified = $true }) }
        }
        AfterEach { $env:RESOURCIVE_HIBP_API_KEY = $script:savedKey }
        It 'does nothing without authorization or a key' {
            $env:RESOURCIVE_HIBP_API_KEY = 'key'
            { Test-ResHibpPrivilegedExposure } | Should -Throw 'skipped:Custom'
            $detail[-1].Reason | Should -Match 'authorization'
            $env:RESOURCIVE_HIBP_API_KEY = ''
            { Test-ResHibpPrivilegedExposure -ClientAuthorized } | Should -Throw 'skipped:Custom'
            $detail[-1].Reason | Should -Match 'RESOURCIVE_HIBP_API_KEY'
        }
        It 'fails when a privileged user is exposed and masks the address' {
            $env:RESOURCIVE_HIBP_API_KEY = 'key'
            Mock Invoke-RestMethod { if ($Uri -like '*breachedDomain*') { [pscustomobject]@{ admin = @('Adobe'); other = @('LinkedIn') } } else { throw [System.Net.Http.HttpRequestException]::new('x') } }
            Test-ResHibpPrivilegedExposure -ClientAuthorized | Should -BeFalse
            $detail[-1].Result | Should -Match 'a\*\*\*@contoso.com'
            $detail[-1].Result | Should -Match '1 other address'
            Test-ResHibpPrivilegedExposure -ClientAuthorized -ShowAddresses | Should -BeFalse
            $detail[-1].Result | Should -Match 'admin@contoso.com'
        }
        It 'passes when nothing is found and is Investigate when everything was refused' {
            $env:RESOURCIVE_HIBP_API_KEY = 'key'
            $notFound = { $response = [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]::NotFound); throw [Microsoft.PowerShell.Commands.HttpResponseException]::new('404', $response) }
            Mock Invoke-RestMethod $notFound
            Test-ResHibpPrivilegedExposure -ClientAuthorized | Should -BeTrue
            $refused = { $response = [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]::Forbidden); throw [Microsoft.PowerShell.Commands.HttpResponseException]::new('403', $response) }
            Mock Invoke-RestMethod $refused
            Test-ResHibpPrivilegedExposure -ClientAuthorized | Should -BeFalse
            $detail[-1].Investigate | Should -BeTrue
        }
    }

    Context 'MP.RESOURCIVE.3007 Secure Score' {
        It 'lists the largest gaps as Investigate' {
            Mock Invoke-MtGraphRequest {
                if ($RelativeUri -like 'security/secureScores*') { @([pscustomobject]@{ currentScore = 50; maxScore = 100; createdDateTime = '2026-10-26'; controlScores = @([pscustomobject]@{ controlName = 'c1'; score = 3 }) }) }
                else { @([pscustomobject]@{ id = 'c1'; title = 'Turn on MFA'; maxScore = 10; service = 'AAD'; userImpact = 'Low'; implementationCost = 'Low'; deprecated = $false }, [pscustomobject]@{ id = 'c2'; title = 'Old'; maxScore = 5; deprecated = $true }, [pscustomobject]@{ id = 'c3'; title = 'Done'; maxScore = 4 }) }
            }
            Test-ResSecureScoreGaps | Should -BeTrue
            $detail[-1].Investigate | Should -BeTrue
            $detail[-1].Result | Should -Match 'Turn on MFA \| AAD \| 7'
            $detail[-1].Result | Should -Not -Match 'Old'
        }
    }

    Context 'MP.RESOURCIVE.3008 tiers and unreadable owners' {
        BeforeEach {
            Mock Invoke-MtGraphRequest {
                switch -Wildcard ($RelativeUri) {
                    'organization' { [pscustomobject]@{ id = 'tenant-1' }; break }
                    'servicePrincipals' {
                        if ($Filter -like "appId eq*") { [pscustomobject]@{ id = 'graph'; appRoles = @([pscustomobject]@{ id = 'role-read'; value = 'User.Read.All' }, [pscustomobject]@{ id = 'role-write'; value = 'Mail.ReadWrite' }) } }
                        else { @([pscustomobject]@{ id = 'sp-ext'; displayName = 'ReadOnlyIsv'; appOwnerOrganizationId = 'other-tenant' }, [pscustomobject]@{ id = 'sp-own'; displayName = 'InternalApp'; appOwnerOrganizationId = 'tenant-1' }) }
                    }
                    'servicePrincipals/sp-ext/appRoleAssignments' { @([pscustomobject]@{ resourceId = 'graph'; appRoleId = 'role-read' }); break }
                    'servicePrincipals/sp-own/appRoleAssignments' { @([pscustomobject]@{ resourceId = 'graph'; appRoleId = 'role-write' }); break }
                    'servicePrincipals/sp-own/owners' { throw 'Forbidden' }
                }
            }
        }
        It 'does not call an owner a missing owner when the read fails, and lists broad read apps without failing them' {
            Test-ResBroadApplicationPermissions | Should -BeFalse
            $detail[-1].Result | Should -Match 'owner could not be read'
            $detail[-1].Result | Should -Not -Match 'no owner'
            $detail[-1].Result | Should -Match 'ReadOnlyIsv'
            Test-ResBroadApplicationPermissions -RiskyPermissions 'Directory.ReadWrite.All' | Should -BeFalse
            $detail[-1].Investigate | Should -BeTrue
        }
    }

    Context 'MP.RESOURCIVE.3008 broad application permissions' {
        BeforeEach {
            Mock Invoke-MtGraphRequest {
                switch -Wildcard ($RelativeUri) {
                    'organization' { [pscustomobject]@{ id = 'tenant-1' }; break }
                    'servicePrincipals' {
                        if ($Filter -like "appId eq*") { [pscustomobject]@{ id = 'graph'; appRoles = @([pscustomobject]@{ id = 'role-mail'; value = 'Mail.ReadWrite' }, [pscustomobject]@{ id = 'role-user'; value = 'User.Read' }) } }
                        else { @([pscustomobject]@{ id = 'sp-ext'; displayName = 'ExtApp'; appOwnerOrganizationId = 'other-tenant' }, [pscustomobject]@{ id = 'sp-own'; displayName = 'OwnedApp'; appOwnerOrganizationId = 'tenant-1' }, [pscustomobject]@{ id = 'sp-ms'; displayName = 'Microsoft'; appOwnerOrganizationId = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a' }) }
                    }
                    '*appRoleAssignments' { @([pscustomobject]@{ resourceId = 'graph'; appRoleId = 'role-mail' }); break }
                    'servicePrincipals/sp-own/owners' { @(); break }
                    'servicePrincipals/*/owners' { @([pscustomobject]@{ id = 'owner' }); break }
                }
            }
        }
        It 'flags the external app and the owner-less internal app but not Microsoft apps' {
            Test-ResBroadApplicationPermissions | Should -BeFalse
            $detail[-1].Result | Should -Match 'ExtApp'
            $detail[-1].Result | Should -Match 'OwnedApp'
            $detail[-1].Result | Should -Not -Match 'Microsoft \|'
        }
        It 'passes when only low-risk permissions are held' {
            Test-ResBroadApplicationPermissions -RiskyPermissions 'Directory.ReadWrite.All' | Should -BeTrue
        }
    }
}
