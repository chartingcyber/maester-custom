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

    Context 'sign-in checks read the raw page that -DisablePaging returns' {
        BeforeAll {
            # With -DisablePaging, Invoke-MtGraphRequest returns the Graph response object, not the rows.
            function New-RawPage { param($Rows, [switch] $More) $r = [pscustomobject]@{ '@odata.context' = 'https://graph.microsoft.com/v1.0/$metadata#auditLogs/signIns'; value = @($Rows) }; if ($More) { $r | Add-Member -NotePropertyName '@odata.nextLink' -NotePropertyValue 'https://graph.microsoft.com/next' }; $r }
            function New-Row { param($App, $User = 'a@c.com', $Code = 0) [pscustomobject]@{ userPrincipalName = $User; clientAppUsed = $App; createdDateTime = '2026-10-20T10:00:00Z'; status = [pscustomobject]@{ errorCode = $Code } } }
        }
        It '3009 fails on legacy sign-ins in a raw page, lists users, and ignores browsers, Unknown and failed sign-ins' {
            Mock Invoke-MtGraphRequest { New-RawPage -Rows @((New-Row 'IMAP4'), (New-Row 'IMAP4'), (New-Row 'Browser' 'b@c.com'), (New-Row 'Unknown' 'c@c.com'), (New-Row 'POP3' 'd@c.com' 50126)) }
            Test-ResLegacyAuthenticationSignIns -LookbackDays 1 | Should -BeFalse
            $detail[-1].Result | Should -Match 'IMAP4 \| 2'
            $detail[-1].Result | Should -Not -Match 'b@c.com|c@c.com|d@c.com'
        }
        It '3009 passes only when every day was read in full and none was legacy' {
            Mock Invoke-MtGraphRequest { New-RawPage -Rows @((New-Row 'Browser')) }
            Test-ResLegacyAuthenticationSignIns -LookbackDays 2 | Should -BeTrue
        }
        It '3009 is Investigate, not a pass, when no legacy is found but days were only partly read' {
            Mock Invoke-MtGraphRequest { New-RawPage -More -Rows @((New-Row 'Unknown')) }
            Test-ResLegacyAuthenticationSignIns -LookbackDays 1 | Should -BeFalse
            $detail[-1].Result | Should -Match 'not a pass'
            $detail[-1].Result | Should -Match 'Partly read'
        }
        It '3009 lists a timed-out day and still assesses the days it read' {
            $script:n = 0
            Mock Invoke-MtGraphRequest { $script:n++; if ($script:n -eq 1) { throw [System.Exception]::new('The request was canceled due to the configured HttpClient.Timeout of 300 seconds elapsing.') } New-RawPage -Rows @((New-Row 'SMTP')) }
            Test-ResLegacyAuthenticationSignIns -LookbackDays 2 | Should -BeFalse
            $detail[-1].Result | Should -Match 'Not read \(request timed out\)'
            $detail[-1].Result | Should -Match 'SMTP'
        }
        It '3009 skips as not assessed when the request times out' {
            Mock Invoke-MtGraphRequest { throw [System.Exception]::new('The request was canceled due to the configured HttpClient.Timeout of 300 seconds elapsing.') }
            { Test-ResLegacyAuthenticationSignIns -LookbackDays 2 } | Should -Throw 'skipped:Custom'
            $detail[-1].Reason | Should -Match 'Not assessed'
        }
        It '3005 assesses the sign-ins inside a raw page' {
            Mock Invoke-MtGraphRequest { New-RawPage -Rows @([pscustomobject]@{ userPrincipalName = 'b@c.com'; isInteractive = $true; status = [pscustomobject]@{ errorCode = 0 }; location = [pscustomobject]@{ countryOrRegion = 'RU' } }) }
            Test-ResSignInsFromUnexpectedCountries -LookbackDays 2 -ExpectedCountries US | Should -BeFalse
            $detail[-1].Result | Should -Match 'b@c.com'
        }
    }

    Context 'MP.RESOURCIVE.3005 sign-in countries' {
        BeforeEach {
            Mock Invoke-MtGraphRequest { @(
                    [pscustomobject]@{ userPrincipalName = 'a@c.com'; isInteractive = $true; status = [pscustomobject]@{ errorCode = 0 }; location = [pscustomobject]@{ countryOrRegion = 'US' } },
                    [pscustomobject]@{ userPrincipalName = 'b@c.com'; isInteractive = $true; status = [pscustomobject]@{ errorCode = 0 }; location = [pscustomobject]@{ countryOrRegion = 'RU' } },
                    [pscustomobject]@{ userPrincipalName = 'c@c.com'; isInteractive = $true; status = [pscustomobject]@{ errorCode = 50126 }; location = [pscustomobject]@{ countryOrRegion = 'CN' } },
                    [pscustomobject]@{ userPrincipalName = 'd@c.com'; isInteractive = $false; status = [pscustomobject]@{ errorCode = 0 }; location = [pscustomobject]@{ countryOrRegion = 'BR' } }) }
        }
        It 'is Investigate without expected countries, fails on others and passes when all are expected' {
            Test-ResSignInsFromUnexpectedCountries -LookbackDays 2 | Should -BeFalse
            $detail[-1].Investigate | Should -BeTrue
            Test-ResSignInsFromUnexpectedCountries -LookbackDays 2 -ExpectedCountries US | Should -BeFalse
            $detail[-1].Result | Should -Match 'b@c.com'
            $detail[-1].Result | Should -Not -Match 'c@c.com|d@c.com'
            Test-ResSignInsFromUnexpectedCountries -LookbackDays 2 -ExpectedCountries 'us', 'ru' | Should -BeTrue
        }
        It 'asks for one capped request per day' {
            Test-ResSignInsFromUnexpectedCountries -LookbackDays 3 -ExpectedCountries US, RU | Out-Null
            Should -Invoke Invoke-MtGraphRequest -Times 3 -Exactly -ParameterFilter { $DisablePaging -and $QueryParameters['$top'] -eq 200 }
        }
        It 'reports days that timed out and still assesses the days that were read' {
            $script:n = 0
            Mock Invoke-MtGraphRequest {
                $script:n++
                if ($script:n -eq 2) { throw [System.Exception]::new('The request was canceled due to the configured HttpClient.Timeout of 300 seconds elapsing.') }
                @([pscustomobject]@{ userPrincipalName = 'b@c.com'; isInteractive = $true; status = [pscustomobject]@{ errorCode = 0 }; location = [pscustomobject]@{ countryOrRegion = 'RU' } })
            }
            Test-ResSignInsFromUnexpectedCountries -LookbackDays 3 -ExpectedCountries US | Should -BeFalse
            $detail[-1].Result | Should -Match 'request timed out'
            $detail[-1].Result | Should -Match 'Coverage is incomplete: 1 of 3'
        }
        It 'skips when no day could be read' {
            Mock Invoke-MtGraphRequest { throw [System.Exception]::new('The request was canceled due to the configured HttpClient.Timeout of 300 seconds elapsing.') }
            { Test-ResSignInsFromUnexpectedCountries -LookbackDays 2 -ExpectedCountries US } | Should -Throw 'skipped:Custom'
            $detail[-1].Reason | Should -Match 'Not assessed'
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
