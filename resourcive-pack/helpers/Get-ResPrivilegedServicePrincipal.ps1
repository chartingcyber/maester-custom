function Get-ResPrivilegedServicePrincipal {
    <#
    .SYNOPSIS
    Returns every application and managed identity that holds a privileged Entra directory role, with the roles held.

    .DESCRIPTION
    Reads the active role assignments and, when the tenant has Entra ID P2 or Governance, the eligible assignments of
    the roles Microsoft marks as privileged, and keeps the service principals. Each one is then read for its type,
    who owns the application, and whether it has client secrets or certificates, because an application that holds
    a privileged role and signs in with a secret is a common way in. Roles that an application holds only through a
    group are not included.

    Returns one object per service principal: Id, DisplayName, AppId, Type, OwnerOrganizationId, IsThirdParty,
    AccountEnabled, SecretCount, CertificateCount, Roles, ActiveRoles, EligibleRoles and EligibleReadable.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        # Leave eligible (PIM) assignments out.
        [switch] $ActiveOnly
    )

    $definitions = @(Invoke-MtGraphRequest -RelativeUri 'roleManagement/directory/roleDefinitions' -ApiVersion beta)
    $privileged = @{}
    foreach ($definition in $definitions) {
        if ($definition.isPrivileged) { $privileged[[string]$definition.id] = [string]$definition.displayName }
    }

    $found = @{}
    $eligibleReadable = $true
    $sources = @(@{ Uri = 'roleManagement/directory/roleAssignments'; Kind = 'Active' })
    if (-not $ActiveOnly) { $sources += @{ Uri = 'roleManagement/directory/roleEligibilityScheduleInstances'; Kind = 'Eligible' } }

    foreach ($source in $sources) {
        try {
            $rows = @(Invoke-MtGraphRequest -RelativeUri $source.Uri -ApiVersion v1.0 -QueryParameters @{ '$expand' = 'principal' } -ErrorAction Stop)
        } catch {
            if ($source.Kind -eq 'Eligible') { $eligibleReadable = $false; continue }
            throw
        }
        foreach ($row in $rows) {
            if ($row.principal.'@odata.type' -ne '#microsoft.graph.servicePrincipal') { continue }
            $roleName = $privileged[[string]$row.roleDefinitionId]
            if (-not $roleName) { continue }
            $id = [string]$row.principal.id
            if (-not $found.ContainsKey($id)) {
                $found[$id] = [pscustomobject]@{
                    Principal     = $row.principal
                    ActiveRoles   = [System.Collections.Generic.List[string]]::new()
                    EligibleRoles = [System.Collections.Generic.List[string]]::new()
                }
            }
            # Index the list directly: assigning an empty list from an if expression would unroll it to $null.
            if ($source.Kind -eq 'Active') {
                if ($roleName -notin $found[$id].ActiveRoles) { $found[$id].ActiveRoles.Add($roleName) }
            } else {
                if ($roleName -notin $found[$id].EligibleRoles) { $found[$id].EligibleRoles.Add($roleName) }
            }
        }
    }

    $tenantId = [string](Get-MgContext).TenantId
    $microsoftTenant = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a'
    foreach ($id in $found.Keys) {
        $entry = $found[$id]
        $principal = $entry.Principal
        # The expanded principal does not carry credentials; read them for each application.
        $detail = $null
        try {
            $detail = Invoke-MtGraphRequest -RelativeUri "servicePrincipals/$id" -ApiVersion v1.0 -Select id, displayName, appId, servicePrincipalType, appOwnerOrganizationId, accountEnabled, passwordCredentials, keyCredentials -ErrorAction Stop
        } catch { }
        $source = if ($detail) { $detail } else { $principal }
        $owner = [string]$source.appOwnerOrganizationId
        [pscustomobject]@{
            Id                  = $id
            DisplayName         = [string]$source.displayName
            AppId               = [string]$source.appId
            Type                = if ($source.servicePrincipalType) { [string]$source.servicePrincipalType } else { 'Application' }
            OwnerOrganizationId = $owner
            IsThirdParty        = [bool]($owner -and $owner -ne $tenantId -and $owner -ne $microsoftTenant)
            AccountEnabled      = $source.accountEnabled
            SecretCount         = if ($detail) { @($detail.passwordCredentials).Count } else { $null }
            CertificateCount    = if ($detail) { @($detail.keyCredentials).Count } else { $null }
            Roles               = @(@($entry.ActiveRoles) + @($entry.EligibleRoles) | Select-Object -Unique)
            ActiveRoles         = @($entry.ActiveRoles)
            EligibleRoles       = @($entry.EligibleRoles)
            EligibleReadable    = $eligibleReadable
        }
    }
}
