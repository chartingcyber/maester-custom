function Add-ResPrivilegedAppFact {
    <#
    .SYNOPSIS
    Adds what the pack knows about an application or managed identity that holds a privileged role.

    .DESCRIPTION
    Adds facts with Add-MtAffectedObjectFact for one service principal from Get-ResPrivilegedServicePrincipal: its type,
    who owns it, how many client secrets and certificates it has, and the roles it holds. An application that holds a
    privileged role and signs in with a secret is marked Risk. The call does nothing in a run that does not collect
    affected objects, and nothing for a service principal without an ID.

    .EXAMPLE
    Add-ResPrivilegedAppFact -App $app
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        # A service principal from Get-ResPrivilegedServicePrincipal.
        [Parameter(Mandatory)]
        [pscustomobject] $App,

        # When the data was read.
        [datetime] $AsOf = [datetime]::UtcNow
    )

    if (-not $App.Id) { return }
    $roles = @($App.Roles | Where-Object { $_ })
    $isManagedIdentity = $App.Type -eq 'ManagedIdentity'
    $facts = [System.Collections.Generic.List[object]]::new()
    $facts.Add(@{ Name = 'Kind'; Value = $(if ($isManagedIdentity) { 'Managed identity' } else { 'Application' }); Tone = 'Info' })
    $facts.Add(@{
            Name  = 'Privileged roles'
            Value = if ($roles.Count -gt 0) { $roles -join ', ' } else { 'None' }
            Tone  = if ($roles.Count -ge 3) { 'Warning' } else { 'Info' }
            Key   = 'resourcive.privilegedRoles'
            Raw   = @($roles)
        })
    $facts.Add(@{
            Name  = 'Owner'
            Value = if ($App.IsThirdParty) { 'Another organization' } elseif ($App.OwnerOrganizationId) { 'This tenant or Microsoft' } else { 'Unknown' }
            Tone  = if ($App.IsThirdParty) { 'Warning' } else { 'Info' }
            Key   = 'resourcive.thirdParty'
            Raw   = [bool]$App.IsThirdParty
        })
    if ($null -ne $App.SecretCount) {
        $facts.Add(@{
                Name  = 'Client secrets'
                Value = [string]$App.SecretCount
                Tone  = if ($App.SecretCount -gt 0) { 'Risk' } else { 'Good' }
                Key   = 'resourcive.secretCount'
                Raw   = [int]$App.SecretCount
            })
    }
    if ($null -ne $App.CertificateCount) {
        $facts.Add(@{ Name = 'Certificates'; Value = [string]$App.CertificateCount; Tone = 'Info'; Key = 'resourcive.certificateCount'; Raw = [int]$App.CertificateCount })
    }
    if ($App.AccountEnabled -eq $false) {
        $facts.Add(@{ Name = 'Account enabled'; Value = 'No'; Tone = 'Warning'; Key = 'resourcive.accountEnabled'; Raw = $false })
    }
    Add-MtAffectedObjectFact -Type ServicePrincipal -Id ([string]$App.Id) -Source 'Resourcive M365 Assessment' -AsOf $AsOf -Fact $facts.ToArray()
}
