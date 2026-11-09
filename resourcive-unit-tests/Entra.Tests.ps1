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

    Context 'sign-in search (Find-ResSignIn, 3005, 3009)' {
        BeforeAll {
            # With -DisablePaging, Invoke-MtGraphRequest returns the Graph response object, not the rows.
            function New-RawPage { param($Rows, [switch] $More) $r = [pscustomobject]@{ '@odata.context' = 'https://graph.microsoft.com/v1.0/$metadata#auditLogs/signIns'; value = @($Rows) }; if ($More) { $r | Add-Member -NotePropertyName '@odata.nextLink' -NotePropertyValue 'https://graph.microsoft.com/next' }; $r }
            function New-Country { param($Country, $User = 'a@c.com', $Code = 0, $Interactive = $true) [pscustomobject]@{ userPrincipalName = $User; isInteractive = $Interactive; createdDateTime = '2026-10-20T10:00:00Z'; appDisplayName = 'Office'; ipAddress = '203.0.113.9'; status = [pscustomobject]@{ errorCode = $Code }; location = [pscustomobject]@{ countryOrRegion = $Country } } }
            function New-Legacy { param($App, $User = 'a@c.com', $Code = 0) [pscustomobject]@{ userPrincipalName = $User; clientAppUsed = $App; createdDateTime = '2026-10-20T10:00:00Z'; appDisplayName = 'Exchange Online'; ipAddress = '203.0.113.9'; status = [pscustomobject]@{ errorCode = $Code } } }
            $script:timeout = 'The request was canceled due to the configured HttpClient.Timeout of 300 seconds elapsing.'
        }

        Context 'Test-ResSignInMatch' {
            It 'matches only successful interactive sign-ins from known unexpected countries' {
                Test-ResSignInMatch -SignIn (New-Country 'RU') -Kind Country -ExpectedCountry US, CA | Should -BeTrue
                Test-ResSignInMatch -SignIn (New-Country 'ca') -Kind Country -ExpectedCountry US, CA | Should -BeFalse
                Test-ResSignInMatch -SignIn (New-Country 'RU' -Code 50126) -Kind Country -ExpectedCountry US | Should -BeFalse
                Test-ResSignInMatch -SignIn (New-Country 'RU' -Interactive $false) -Kind Country -ExpectedCountry US | Should -BeFalse
                Test-ResSignInMatch -SignIn (New-Country '') -Kind Country -ExpectedCountry US | Should -BeFalse
            }
            It 'matches successful sign-ins by a named legacy client only' {
                Test-ResSignInMatch -SignIn (New-Legacy 'IMAP4') -Kind Legacy | Should -BeTrue
                Test-ResSignInMatch -SignIn (New-Legacy 'Browser') -Kind Legacy | Should -BeFalse
                Test-ResSignInMatch -SignIn (New-Legacy 'Mobile Apps and Desktop clients') -Kind Legacy | Should -BeFalse
                Test-ResSignInMatch -SignIn (New-Legacy 'Unknown') -Kind Legacy | Should -BeFalse
                Test-ResSignInMatch -SignIn (New-Legacy 'POP3' -Code 50126) -Kind Legacy | Should -BeFalse
            }
        }

        Context 'Find-ResSignIn' {
            It 'searches the whole period with one filtered request that stops at ten matches' {
                Mock Invoke-MtGraphRequest { New-RawPage -Rows @((New-Country 'RU'), (New-Country 'CN' 'b@c.com')) }
                $r = Find-ResSignIn -Kind Country -ExpectedCountry US, CA -ServerFilter
                $r.Mode | Should -Be 'ServerFilter'
                $r.Complete | Should -BeTrue
                $r.AtLeast | Should -BeFalse
                @($r.Matches).Count | Should -Be 2
                Should -Invoke Invoke-MtGraphRequest -Times 1 -Exactly -ParameterFilter {
                    $ApiVersion -eq 'v1.0' -and $DisablePaging -and $QueryParameters['$top'] -eq 10 -and
                    $Filter -match "location/countryOrRegion ne 'US'" -and $Filter -match "location/countryOrRegion ne 'CA'" -and $Filter -match 'status/errorCode eq 0'
                }
            }
            It 'reads day by day by default and never sends the whole-period filtered request' {
                Mock Invoke-MtGraphRequest { New-RawPage -Rows @((New-Country 'US')) }
                $r = Find-ResSignIn -Kind Country -ExpectedCountry US, CA -LookbackDays 3
                $r.Mode | Should -Be 'PerDay'
                $r.FallbackReason | Should -BeNullOrEmpty
                $r.Complete | Should -BeTrue
                Should -Invoke Invoke-MtGraphRequest -Times 3 -Exactly -ParameterFilter { $QueryParameters['$top'] -eq 200 -and $Filter -notmatch 'location/countryOrRegion' }
            }
            It 'says at least when the limit is reached' {
                Mock Invoke-MtGraphRequest { New-RawPage -Rows @(1..10 | ForEach-Object { New-Country 'RU' "u$_@c.com" }) }
                $r = Find-ResSignIn -Kind Country -ExpectedCountry US -ServerFilter
                $r.AtLeast | Should -BeTrue
                @($r.Matches).Count | Should -Be 10
            }
            It 'treats an empty server result as a complete answer' {
                Mock Invoke-MtGraphRequest { New-RawPage -Rows @() }
                $r = Find-ResSignIn -Kind Country -ExpectedCountry US -ServerFilter
                @($r.Matches).Count | Should -Be 0
                $r.Complete | Should -BeTrue
            }
            It 'reads day by day when Graph refuses the filter, and stops at ten matches' {
                Mock Invoke-MtGraphRequest {
                    if ($QueryParameters['$top'] -eq 10) { throw 'BadRequest: Unsupported filter on location' }
                    New-RawPage -Rows @(1..15 | ForEach-Object { New-Country 'RU' "u$_@c.com" })
                }
                $r = Find-ResSignIn -Kind Country -ExpectedCountry US -LookbackDays 3 -ServerFilter
                $r.Mode | Should -Be 'PerDay'
                $r.FallbackReason | Should -Match 'not usable'
                @($r.Matches).Count | Should -Be 10
                $r.AtLeast | Should -BeTrue
                @($r.Days | Where-Object { $_.State -like 'Not needed*' }).Count | Should -Be 2
                Should -Invoke Invoke-MtGraphRequest -Times 2 -Exactly
            }
            It 'ignores failed, non-interactive, unknown-country and expected sign-ins when reading day by day' {
                Mock Invoke-MtGraphRequest {
                    if ($QueryParameters['$top'] -eq 10) { throw $script:timeout }
                    New-RawPage -Rows @((New-Country 'US'), (New-Country 'RU' 'f@c.com' 50126), (New-Country 'BR' 'n@c.com' 0 $false), (New-Country ''), (New-Country 'GB' 'g@c.com'))
                }
                $r = Find-ResSignIn -Kind Country -ExpectedCountry US, CA -LookbackDays 1
                @($r.Matches).Count | Should -Be 1
                $r.Matches[0].userPrincipalName | Should -Be 'g@c.com'
                $r.Complete | Should -BeTrue
            }
            It 'is incomplete when a day times out or is only partly read' {
                $script:n = 0
                Mock Invoke-MtGraphRequest {
                    if ($QueryParameters['$top'] -eq 10) { throw $script:timeout }
                    $script:n++
                    if ($script:n -eq 1) { throw $script:timeout }
                    New-RawPage -More -Rows @((New-Country 'US'))
                }
                $r = Find-ResSignIn -Kind Country -ExpectedCountry US -LookbackDays 2
                $r.Complete | Should -BeFalse
                ($r.Days | ForEach-Object State) -join ';' | Should -Match 'request timed out'
                ($r.Days | ForEach-Object State) -join ';' | Should -Match 'Partly read'
            }
            It 'does not retry an authorization error' {
                Mock Invoke-MtGraphRequest { throw 'Forbidden' }
                { Find-ResSignIn -Kind Country -ExpectedCountry US } | Should -Throw 'skipped:Custom'
                Should -Invoke Invoke-MtGraphRequest -Times 1 -Exactly
            }
            It 'searches legacy sign-ins in the beta log, including non-interactive ones' {
                Mock Invoke-MtGraphRequest { New-RawPage -Rows @((New-Legacy 'IMAP4')) }
                $r = Find-ResSignIn -Kind Legacy -ServerFilter
                $r.Mode | Should -Be 'ServerFilter'
                $r.NonInteractiveAssessed | Should -BeTrue
                Should -Invoke Invoke-MtGraphRequest -Times 1 -Exactly -ParameterFilter {
                    $ApiVersion -eq 'beta' -and $Filter -match 'nonInteractiveUser' -and $Filter -match "clientAppUsed ne 'Browser'" -and $Filter -match 'status/errorCode eq 0'
                }
            }
            It 'falls back to v1.0 when the beta log is refused, and is then never complete' {
                Mock Invoke-MtGraphRequest {
                    if ($ApiVersion -eq 'beta') { throw 'BadRequest: Unsupported filter signInEventTypes' }
                    New-RawPage -Rows @((New-Legacy 'Browser'))
                }
                $r = Find-ResSignIn -Kind Legacy -LookbackDays 2 -ServerFilter
                $r.Mode | Should -Be 'PerDay'
                $r.NonInteractiveAssessed | Should -BeFalse
                $r.Complete | Should -BeFalse
                @($r.Matches).Count | Should -Be 0
            }
        }

        Context '3005 sign-in countries' {
            It 'defaults to US and CA, fails on a sign-in from another country and lists it' {
                Mock Invoke-MtGraphRequest { New-RawPage -Rows @((New-Country 'RU' 'b@c.com')) }
                Test-ResSignInsFromUnexpectedCountries | Should -BeFalse
                $detail[-1].Result | Should -Match 'b@c.com'
                $detail[-1].Result | Should -Match 'outside US, CA'
                $detail[-1].Result | Should -Match 'ExpectedCountries'
                $detail[-1].Result | Should -Match 'iso.org'
            }
            It 'passes when nothing is outside the expected countries and the whole period was searched' {
                Mock Invoke-MtGraphRequest { New-RawPage -Rows @() }
                Test-ResSignInsFromUnexpectedCountries | Should -BeTrue
                $detail[-1].Result | Should -Match 'Well done'
            }
            It 'uses the countries it is given instead of the default' {
                Mock Invoke-MtGraphRequest { New-RawPage -Rows @((New-Country 'GB'), (New-Country 'IE' 'i@c.com')) }
                Test-ResSignInsFromUnexpectedCountries -ExpectedCountries 'gb', 'IE' | Should -BeTrue
                $detail[-1].Result | Should -Match 'outside GB, IE'
                Mock Invoke-MtGraphRequest { New-RawPage -Rows @((New-Country 'US' 'u@c.com')) }
                Test-ResSignInsFromUnexpectedCountries -ExpectedCountries 'gb', 'IE' | Should -BeFalse
                $detail[-1].Result | Should -Match 'u@c.com'
            }
            It 'rejects a country that is not a two-letter code' {
                { Test-ResSignInsFromUnexpectedCountries -ExpectedCountries 'USA' } | Should -Throw
            }
            It 'is Investigate, not a pass, when no match is found but days were not read' {
                $script:n = 0
                Mock Invoke-MtGraphRequest {
                    if ($QueryParameters['$top'] -eq 10) { throw $script:timeout }
                    $script:n++
                    if ($script:n -eq 2) { throw $script:timeout }
                    New-RawPage -Rows @((New-Country 'US'))
                }
                Test-ResSignInsFromUnexpectedCountries -LookbackDays 3 | Should -BeFalse
                $detail[-1].Investigate | Should -BeTrue
                $detail[-1].Result | Should -Match 'not a pass'
                $detail[-1].Result | Should -Match 'request timed out'
            }
            It 'skips when no day could be read' {
                Mock Invoke-MtGraphRequest { throw $script:timeout }
                { Test-ResSignInsFromUnexpectedCountries -LookbackDays 2 } | Should -Throw 'skipped:Custom'
                $detail[-1].Reason | Should -Match 'Not assessed'
            }
        }

        Context '3009 legacy sign-ins' {
            It 'is skipped as Not assessed unless SearchLog is set, without calling Graph' {
                Mock Invoke-MtGraphRequest { throw 'must not be called' }
                { Test-ResLegacyAuthenticationSignIns } | Should -Throw 'skipped:Custom'
                $detail[-1].Reason | Should -Match 'Not assessed'
                $detail[-1].Reason | Should -Match 'MT.1033'
                Should -Invoke Invoke-MtGraphRequest -Times 0 -Exactly
            }
            It 'fails on a legacy sign-in and lists user and protocol' {
                Mock Invoke-MtGraphRequest { New-RawPage -Rows @((New-Legacy 'IMAP4' 'm@c.com'), (New-Legacy 'IMAP4' 'm@c.com')) }
                Test-ResLegacyAuthenticationSignIns -SearchLog | Should -BeFalse
                $detail[-1].Result | Should -Match 'm@c.com'
                $detail[-1].Result | Should -Match 'IMAP4'
            }
            It 'passes when none is found and the whole period, interactive and non-interactive, was searched' {
                Mock Invoke-MtGraphRequest { New-RawPage -Rows @() }
                Test-ResLegacyAuthenticationSignIns -SearchLog | Should -BeTrue
                $detail[-1].Result | Should -Match 'non-interactive'
            }
            It 'is Investigate, never a pass, when only the v1.0 log could be read' {
                Mock Invoke-MtGraphRequest {
                    if ($ApiVersion -eq 'beta') { throw 'BadRequest: Unsupported filter signInEventTypes' }
                    New-RawPage -Rows @((New-Legacy 'Browser'))
                }
                Test-ResLegacyAuthenticationSignIns -SearchLog -LookbackDays 2 | Should -BeFalse
                $detail[-1].Investigate | Should -BeTrue
                $detail[-1].Result | Should -Match 'Non-interactive sign-ins'
            }
            It 'skips as not assessed when every request times out' {
                Mock Invoke-MtGraphRequest { throw $script:timeout }
                { Test-ResLegacyAuthenticationSignIns -SearchLog -LookbackDays 2 } | Should -Throw 'skipped:Custom'
                $detail[-1].Reason | Should -Match 'Not assessed'
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
