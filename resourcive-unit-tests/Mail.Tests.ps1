# Runs the mail checks of the RESOURCIVE pack with Exchange Online and Graph stubbed.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../powershell/Maester.psd1') -Force -ErrorAction Stop
    foreach ($file in (Get-ChildItem -Path (Join-Path $PSScriptRoot '../resourcive-pack/helpers') -Filter '*.ps1')) { . $file.FullName }
    foreach ($file in (Get-ChildItem -Path (Join-Path $PSScriptRoot '../resourcive-pack/mail') -Filter 'Test.*.ps1')) { . $file.FullName }
    # Exchange Online cmdlets exist only in a connected session; stub them so that they can be mocked.
    function Get-EXOMailbox { param($ResultSize, $RecipientTypeDetails, $Properties) }
    function Get-EXORecipient { param($Identity, $Properties) }
    function Get-InboxRule { param($Mailbox, [switch] $IncludeHidden) }
    function Get-OutboundConnector { param() }

    function New-Recipient { param([string] $Upn) [pscustomobject]@{ DisplayName = $Upn; UserPrincipalName = $Upn; PrimarySmtpAddress = $Upn; Domain = ($Upn -split '@')[1]; Addresses = @($Upn) } }
}

Describe 'Mail checks' {
    BeforeEach {
        $script:detail = @()
        Mock Assert-ResLicense { }
        Mock Add-MtTestResultDetail {
            $script:detail += [pscustomobject]@{ Result = $Result; Investigate = [bool]$Investigate; Skipped = $SkippedBecause }
            if ($SkippedBecause) { throw "skipped:$SkippedBecause" }
        }
        Mock Resolve-ResGroupMemberAddress { param($Identity, $Cache) , @() }
    }

    Context 'MP.RESOURCIVE.2001 Safe Links and Safe Attachments coverage' {
        BeforeEach {
            Mock Get-ResMailRecipient { @((New-Recipient 'a@contoso.com'), (New-Recipient 'b@contoso.com')) }
            Mock Get-MtExo { }
        }
        It 'passes when Built-in protection reaches everyone' {
            Mock Get-MtExo { if ($Request -eq 'ATPBuiltInProtectionRule') { [pscustomobject]@{ Name = 'ATP Built-In Protection Rule' } } }
            Test-ResSafeLinksAttachmentsCoverage | Should -BeTrue
            $detail[-1].Result | Should -Match 'covered by Built-in protection only'
        }
        It 'fails and names the user that an exclusion leaves uncovered' {
            Mock Get-MtExo { if ($Request -eq 'ATPBuiltInProtectionRule') { [pscustomobject]@{ Name = 'ATP Built-In Protection Rule'; ExceptIfSentTo = @('b@contoso.com') } } }
            Test-ResSafeLinksAttachmentsCoverage | Should -BeFalse
            $detail[-1].Result | Should -Match 'b@contoso.com'
            $detail[-1].Result | Should -Not -Match '\* a@contoso.com'
        }
        It 'counts a custom Safe Links rule for one product only' {
            Mock Get-MtExo {
                switch ($Request) {
                    'ATPBuiltInProtectionRule' { [pscustomobject]@{ Name = 'ATP Built-In Protection Rule'; ExceptIfSentTo = @('b@contoso.com') } }
                    'SafeLinksRule' { [pscustomobject]@{ Name = 'Pilot'; State = 'Enabled'; SentTo = @('b@contoso.com') } }
                }
            }
            Test-ResSafeLinksAttachmentsCoverage | Should -BeFalse
            $detail[-1].Result | Should -Match 'Safe Links:\*\* 2 of 2'
            $detail[-1].Result | Should -Match 'Safe Attachments:\*\* 1 of 2'
        }
        It 'counts a Standard preset rule' {
            Mock Get-MtExo {
                switch ($Request) {
                    'ATPBuiltInProtectionRule' { [pscustomobject]@{ Name = 'ATP Built-In Protection Rule'; ExceptIfRecipientDomainIs = @('contoso.com') } }
                    'ATPProtectionPolicyRule' { [pscustomobject]@{ Name = 'Standard Preset Security Policy'; State = 'Enabled'; RecipientDomainIs = @('contoso.com') } }
                }
            }
            Test-ResSafeLinksAttachmentsCoverage | Should -BeTrue
        }
        It 'is not applicable with no mailboxes' {
            Mock Get-ResMailRecipient { }
            { Test-ResSafeLinksAttachmentsCoverage } | Should -Throw 'skipped:NotApplicable'
        }
    }

    Context 'MP.RESOURCIVE.2002 privileged users and Strict' {
        BeforeEach {
            Mock Get-ResMailRecipient { @((New-Recipient 'admin@contoso.com'), (New-Recipient 'user@contoso.com')) }
            Mock Get-ResPrivilegedUser { [pscustomobject]@{ UserPrincipalName = 'admin@contoso.com'; Mail = 'admin@contoso.com'; Roles = @('Global Administrator'); EligibleReadable = $true } }
        }
        It 'passes when both Strict rules include the administrator' {
            Mock Get-MtExo { [pscustomobject]@{ Name = 'Strict Preset Security Policy'; State = 'Enabled'; SentTo = @('admin@contoso.com') } }
            Test-ResPrivilegedUsersStrictPreset | Should -BeTrue
        }
        It 'fails when the administrator is only in Standard' {
            Mock Get-MtExo { [pscustomobject]@{ Name = 'Standard Preset Security Policy'; State = 'Enabled' } }
            Test-ResPrivilegedUsersStrictPreset | Should -BeFalse
            $detail[-1].Result | Should -Match 'Standard'
        }
        It 'fails when no rule covers the administrator, and skips a privileged user without a mailbox' {
            Mock Get-MtExo { }
            Test-ResPrivilegedUsersStrictPreset | Should -BeFalse
            Mock Get-ResPrivilegedUser { [pscustomobject]@{ UserPrincipalName = 'nobox@contoso.com'; Mail = ''; Roles = @('Global Administrator'); EligibleReadable = $true } }
            { Test-ResPrivilegedUsersStrictPreset } | Should -Throw 'skipped:NotApplicable'
        }
    }

    Context 'MP.RESOURCIVE.2003 mailbox forwarding' {
        BeforeEach { Mock Get-MtExo { [pscustomobject]@{ DomainName = 'contoso.com' } } }
        It 'passes with none, lists internal forwards, and fails on an external one' {
            Mock Get-EXOMailbox { @([pscustomobject]@{ UserPrincipalName = 'a@contoso.com'; ForwardingSmtpAddress = $null; ForwardingAddress = $null }) }
            Test-ResMailboxForwarding | Should -BeTrue
            Mock Get-EXOMailbox { @([pscustomobject]@{ UserPrincipalName = 'a@contoso.com'; ForwardingSmtpAddress = 'smtp:b@contoso.com'; ForwardingAddress = $null }) }
            Test-ResMailboxForwarding | Should -BeTrue
            $detail[-1].Result | Should -Match 'Internal forwards'
            Mock Get-EXOMailbox { @([pscustomobject]@{ UserPrincipalName = 'a@contoso.com'; ForwardingSmtpAddress = 'smtp:evil@attacker.example'; ForwardingAddress = $null; DeliverToMailboxAndForward = $true }) }
            Test-ResMailboxForwarding | Should -BeFalse
            $detail[-1].Result | Should -Match 'evil@attacker.example'
        }
        It 'resolves a forwarding recipient that is an external contact' {
            Mock Get-EXOMailbox { @([pscustomobject]@{ UserPrincipalName = 'a@contoso.com'; ForwardingAddress = 'Contact1' }) }
            Mock Get-EXORecipient { [pscustomobject]@{ ExternalEmailAddress = 'SMTP:x@other.example'; PrimarySmtpAddress = $null } }
            Test-ResMailboxForwarding | Should -BeFalse
        }
    }

    Context 'MP.RESOURCIVE.2003 transport note and 2006 allow-list and 2001 text' {
        It '2003 says whether the external forwards are probably blocked in transit' {
            Mock Get-EXOMailbox { @([pscustomobject]@{ UserPrincipalName = 'a@contoso.com'; ForwardingSmtpAddress = 'smtp:evil@attacker.example'; DeliverToMailboxAndForward = $true }) }
            Mock Get-MtExo {
                switch ($Request) {
                    'AcceptedDomain' { [pscustomobject]@{ DomainName = 'contoso.com' }; break }
                    'HostedOutboundSpamFilterPolicy' { [pscustomobject]@{ Name = 'Default'; AutoForwardingMode = 'Automatic' }; break }
                    'RemoteDomain' { [pscustomobject]@{ DomainName = '*'; AutoForwardEnabled = $false }; break }
                }
            }
            Test-ResMailboxForwarding | Should -BeFalse
            $detail[-1].Result | Should -Match 'probably stopped in transit'
            Mock Get-MtExo {
                switch ($Request) {
                    'AcceptedDomain' { [pscustomobject]@{ DomainName = 'contoso.com' }; break }
                    'HostedOutboundSpamFilterPolicy' { [pscustomobject]@{ Name = 'Default'; AutoForwardingMode = 'On' }; break }
                    'RemoteDomain' { [pscustomobject]@{ DomainName = '*'; AutoForwardEnabled = $true }; break }
                }
            }
            Test-ResMailboxForwarding | Should -BeFalse
            $detail[-1].Result | Should -Match 'can deliver mail'
        }
        It '2006 lists an allowed external address without failing and still fails on others' {
            Mock Get-MtExo { if ($Request -eq 'AcceptedDomain') { [pscustomobject]@{ DomainName = 'contoso.com' } } else { [pscustomobject]@{ Name = 'Jira'; State = 'Enabled'; CopyTo = @('support@atlassian.example') } } }
            Test-ResTransportRulesExternalCopy | Should -BeFalse
            Test-ResTransportRulesExternalCopy -AllowedExternal 'atlassian.example' | Should -BeTrue
            $detail[-1].Result | Should -Match 'Allowed by the AllowedExternal'
            Test-ResTransportRulesExternalCopy -AllowedExternal 'support@atlassian.example' | Should -BeTrue
            Test-ResTransportRulesExternalCopy -AllowedExternal 'other.example' | Should -BeFalse
        }
    }

    Context 'MP.RESOURCIVE.2004 auto-forwarding' {
        It 'passes when blocked and fails when a policy or remote domain allows it' {
            Mock Get-MtExo { if ($Request -eq 'HostedOutboundSpamFilterPolicy') { [pscustomobject]@{ Name = 'Default'; AutoForwardingMode = 'Automatic' } } else { [pscustomobject]@{ DomainName = '*'; AutoForwardEnabled = $false } } }
            Test-ResAutoForwardingBlocked | Should -BeTrue
            Mock Get-MtExo { if ($Request -eq 'HostedOutboundSpamFilterPolicy') { [pscustomobject]@{ Name = 'Default'; AutoForwardingMode = 'On' } } else { [pscustomobject]@{ DomainName = '*'; AutoForwardEnabled = $false } } }
            Test-ResAutoForwardingBlocked | Should -BeFalse
            Mock Get-MtExo { if ($Request -eq 'HostedOutboundSpamFilterPolicy') { [pscustomobject]@{ Name = 'Default'; AutoForwardingMode = 'Off' } } else { [pscustomobject]@{ DomainName = '*'; AutoForwardEnabled = $true } } }
            Test-ResAutoForwardingBlocked | Should -BeFalse
        }
    }

    Context 'MP.RESOURCIVE.2005 inbox rules' {
        BeforeEach {
            Mock Get-MtExo { [pscustomobject]@{ DomainName = 'contoso.com' } }
            Mock Get-ResMailRecipient { @((New-Recipient 'admin@contoso.com')) }
            Mock Get-ResPrivilegedUser { [pscustomobject]@{ UserPrincipalName = 'admin@contoso.com'; Mail = 'admin@contoso.com' } }
        }
        It 'passes for ordinary rules' {
            Mock Get-InboxRule { @([pscustomobject]@{ Name = 'Newsletters'; Enabled = $true; MoveToFolder = 'Newsletters'; SubjectContainsWords = @('digest') }) }
            Test-ResSuspiciousInboxRules | Should -BeTrue
        }
        It 'flags an external forward, a hiding rule with suspicious words and a nameless rule' {
            Mock Get-InboxRule { @(
                    [pscustomobject]@{ Name = 'fwd'; Enabled = $true; ForwardTo = @('"X" [SMTP:x@attacker.example]') },
                    [pscustomobject]@{ Name = 'hide'; Enabled = $true; DeleteMessage = $true; SubjectContainsWords = @('invoice') },
                    [pscustomobject]@{ Name = '.'; Enabled = $true }) }
            Test-ResSuspiciousInboxRules | Should -BeFalse
            $detail[-1].Result | Should -Match 'x@attacker.example'
            $detail[-1].Result | Should -Match 'hides mail matching: invoice'
            $detail[-1].Result | Should -Match 'empty or one-character name'
        }
        It 'ignores disabled rules and does not report unreadable mailboxes as passing' {
            Mock Get-InboxRule { @([pscustomobject]@{ Name = 'fwd'; Enabled = $false; ForwardTo = @('x@attacker.example') }) }
            Test-ResSuspiciousInboxRules | Should -BeTrue
            Mock Get-InboxRule { throw 'not allowed' }
            Test-ResSuspiciousInboxRules | Should -BeFalse
            $detail[-1].Investigate | Should -BeTrue
        }
    }

    Context 'MP.RESOURCIVE.2006 transport rules' {
        BeforeEach { Mock Get-MtExo { if ($Request -eq 'AcceptedDomain') { [pscustomobject]@{ DomainName = 'contoso.com' } } } }
        It 'passes without external copies and fails with one' {
            Mock Get-MtExo { if ($Request -eq 'AcceptedDomain') { [pscustomobject]@{ DomainName = 'contoso.com' } } else { [pscustomobject]@{ Name = 'Archive'; State = 'Enabled'; BlindCopyTo = @('archive@contoso.com') } } }
            Test-ResTransportRulesExternalCopy | Should -BeTrue
            Mock Get-MtExo { if ($Request -eq 'AcceptedDomain') { [pscustomobject]@{ DomainName = 'contoso.com' } } else { [pscustomobject]@{ Name = 'Leak'; State = 'Enabled'; BlindCopyTo = @('x@attacker.example') } } }
            Test-ResTransportRulesExternalCopy | Should -BeFalse
        }
        It 'ignores disabled rules and lists name-only recipients without failing' {
            Mock Get-MtExo { if ($Request -eq 'AcceptedDomain') { [pscustomobject]@{ DomainName = 'contoso.com' } } else { @([pscustomobject]@{ Name = 'Off'; State = 'Disabled'; BlindCopyTo = @('x@attacker.example') }, [pscustomobject]@{ Name = 'ByName'; State = 'Enabled'; CopyTo = @('Some Contact') }) } }
            Test-ResTransportRulesExternalCopy | Should -BeTrue
            $detail[-1].Result | Should -Match 'Some Contact'
        }
    }

    Context 'MP.RESOURCIVE.2007 connectors' {
        It 'fails for an open inbound connector and passes for an IP-restricted one' {
            Mock Get-OutboundConnector { }
            Mock Get-MtExo { [pscustomobject]@{ Name = 'Open'; Enabled = $true; ConnectorType = 'Partner'; SenderDomains = @('smtp:*;1'); SenderIPAddresses = @() } }
            Test-ResMailConnectorsRestricted | Should -BeFalse
            Mock Get-MtExo { [pscustomobject]@{ Name = 'Partner'; Enabled = $true; ConnectorType = 'Partner'; SenderDomains = @('smtp:*;1'); SenderIPAddresses = @('203.0.113.5') } }
            Test-ResMailConnectorsRestricted | Should -BeTrue
            Mock Get-MtExo { [pscustomobject]@{ Name = 'Cert'; Enabled = $true; ConnectorType = 'Partner'; SenderDomains = @('smtp:fabrikam.com;1'); TlsSenderCertificateName = 'mail.fabrikam.com' } }
            Test-ResMailConnectorsRestricted | Should -BeTrue
        }
        It 'treats a connector with no sender domains and no restriction as open, and ignores disabled ones' {
            Mock Get-OutboundConnector { }
            Mock Get-MtExo { [pscustomobject]@{ Name = 'NoDomains'; Enabled = $true; ConnectorType = 'OnPremises' } }
            Test-ResMailConnectorsRestricted | Should -BeFalse
            Mock Get-MtExo { }
            Test-ResMailConnectorsRestricted | Should -BeTrue
        }
        It 'passes with no open inbound connector and lists an outbound smart-host connector as information' {
            Mock Get-MtExo { }
            Mock Get-OutboundConnector { [pscustomobject]@{ Name = 'Gateway'; Enabled = $true; SmartHosts = @('mx.gateway.example'); RecipientDomains = @('*') } }
            Test-ResMailConnectorsRestricted | Should -BeTrue
            $detail[-1].Investigate | Should -BeFalse
            $detail[-1].Result | Should -Match 'mx.gateway.example'
        }
    }
}
