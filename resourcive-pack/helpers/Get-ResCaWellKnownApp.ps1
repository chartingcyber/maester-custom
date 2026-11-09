function Get-ResCaWellKnownApp {
    <#
    .SYNOPSIS
    Returns the first-party applications that the What If scenarios use when a policy targets a whole app group.

    .DESCRIPTION
    The What If API needs an application ID: a group such as Office 365 or Microsoft Admin Portals does not match.
    These IDs are published on Microsoft Learn ("Commonly used Microsoft first-party services and portal apps",
    "Conditional Access: Target resources" and the Dev Box Conditional Access article). Group is M365 for the
    Microsoft 365 workloads, AdminPortal for the portals and Azure for Azure management.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    @(
        [pscustomobject]@{ Key = 'exo'; Name = 'Office 365 Exchange Online'; Id = '00000002-0000-0ff1-ce00-000000000000'; Group = 'M365' }
        [pscustomobject]@{ Key = 'spo'; Name = 'Office 365 SharePoint Online'; Id = '00000003-0000-0ff1-ce00-000000000000'; Group = 'M365' }
        [pscustomobject]@{ Key = 'teams'; Name = 'Microsoft Teams Services'; Id = 'cc15fd57-2c6c-4117-a88c-83b1d56b4bbe'; Group = 'M365' }
        [pscustomobject]@{ Key = 'portals'; Name = 'Azure portal (Microsoft Admin Portals group)'; Id = 'c44b4083-3bb0-49c1-b47d-974e53cbdf3c'; Group = 'AdminPortal' }
        [pscustomobject]@{ Key = 'arm'; Name = 'Windows Azure Service Management API'; Id = '797f4846-ba00-4fd7-ba43-dac1f8f63013'; Group = 'Azure' }
    )
}
