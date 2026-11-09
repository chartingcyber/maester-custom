function Test-ResDelegatedAdminRelationships {
    <#
    .SYNOPSIS
    Checks delegated admin (GDAP) relationships for highly privileged roles and long lifetimes, using a partner-side export when the tenant cannot see them.

    .DESCRIPTION
    GDAP relationships are normally visible only to the partner (MSP) tenant that holds them. The check first tries to
    read tenantRelationships/delegatedAdminRelationships from the connected tenant. When that is not possible it
    reads PartnerExportPath, a JSON file that the MSP exports from Partner Center or Microsoft Graph, for example
    with Get-MgTenantRelationshipDelegatedAdminRelationship | ConvertTo-Json -Depth 10. Without either, the check is
    skipped and says what is needed.

    Active relationships are flagged when they grant a highly privileged role (Global Administrator, Privileged Role
    Administrator, Privileged Authentication Administrator, Application Administrator, Exchange Administrator,
    Security Administrator, User Administrator) or last longer than MaximumDays.
    #>
    [MaesterTest(
        Id           = 'MP.RESOURCIVE.3004',
        Title        = 'Delegated admin (GDAP) relationships do not grant standing high-privilege roles for long periods.',
        Product      = 'entra',
        Feature      = 'roles',
        Area         = 'privileged-access',
        ResourceType = 'Tenant',
        Severity     = 'Medium',
        UserImpact   = 'Low',
        ImplementationCost = 'Medium',
        Mitre        = ('T1199', 'T1078.004'),
        Control      = ('nist-800-53-r5:AC-6', 'nist-800-53-r5:AC-2'),
        Service      = 'Graph',
        Permission   = 'Graph:Scope:DelegatedAdminRelationship.Read.All'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        # A JSON export of delegatedAdminRelationships from the partner side. Used when the tenant cannot read them.
        [string] $PartnerExportPath,

        # The longest lifetime, in days, that a relationship with a privileged role may have remaining.
        [ValidateRange(1, 730)]
        [int] $MaximumDays = 180
    )

    $relationships = $null
    $source = ''
    try {
        $relationships = @(Invoke-MtGraphRequest -RelativeUri 'tenantRelationships/delegatedAdminRelationships' -ApiVersion v1.0 -ErrorAction Stop)
        $source = 'Microsoft Graph (partner tenant)'
    } catch {
        $relationships = $null
    }
    if (($null -eq $relationships -or $relationships.Count -eq 0) -and $PartnerExportPath) {
        if (-not (Test-Path -LiteralPath $PartnerExportPath -PathType Leaf)) {
            Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason "Not assessed: the partner export file '$PartnerExportPath' does not exist."
        }
        $parsed = Get-Content -LiteralPath $PartnerExportPath -Raw | ConvertFrom-Json
        # An export is either the array itself or a Graph response with a value property. Do not read .value on an array: it enumerates to nulls.
        $relationships = if ($parsed -is [array]) { @($parsed) } elseif ($parsed.PSObject.Properties['value']) { @($parsed.value) } else { @($parsed) }
        $source = "partner export $PartnerExportPath"
    }
    if ($null -eq $relationships -or $relationships.Count -eq 0) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason 'Not assessed: GDAP relationships are visible only from the partner (MSP) tenant. Set the PartnerExportPath parameter to a JSON export of delegatedAdminRelationships from Partner Center or Microsoft Graph, or run this check from the partner tenant. Needs DelegatedAdminRelationship.Read.All on the partner side.'
    }

    # Role template IDs of the highly privileged roles (Microsoft Entra built-in roles).
    $privilegedRoles = @{
        '62e90394-69f5-4237-9190-012177145e10' = 'Global Administrator'
        'e8611ab8-c189-46e8-94e1-60213ab1f814' = 'Privileged Role Administrator'
        '7be44c8a-adaf-4e2a-84d6-ab2649e08a13' = 'Privileged Authentication Administrator'
        '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' = 'Application Administrator'
        '29232cdf-9323-42fd-ade2-1d097af3e4de' = 'Exchange Administrator'
        '194ae4cb-b126-40b2-bd5b-6091b380977d' = 'Security Administrator'
        'fe930be7-5e62-47db-91af-98c3a49a38b1' = 'User Administrator'
    }

    $now = (Get-Date).ToUniversalTime()
    $findings = foreach ($relationship in @($relationships | Where-Object { $_.status -eq 'active' })) {
        $roles = @($relationship.accessDetails.unifiedRoles | ForEach-Object { $privilegedRoles[[string]$_.roleDefinitionId] } | Where-Object { $_ })
        $end = if ($relationship.endDateTime) { ([datetime]$relationship.endDateTime).ToUniversalTime() } else { $null }
        $days = if ($end) { [math]::Floor(($end - $now).TotalDays) } else { $null }
        $reasons = @()
        if ($roles.Count -gt 0) { $reasons += "grants $($roles -join ', ')" }
        if ($roles.Count -gt 0 -and $null -ne $days -and $days -gt $MaximumDays) { $reasons += "ends in $days days (limit $MaximumDays)" }
        if ($reasons.Count -gt 0) {
            [pscustomobject]@{ Relationship = [string]$relationship.displayName; Customer = [string]$relationship.customer.displayName; Reason = ($reasons -join '; ') }
        }
    }
    $findings = @($findings | Where-Object { $null -ne $_ })
    $active = @($relationships | Where-Object { $_.status -eq 'active' }).Count
    $summary = "Read $($relationships.Count) relationship(s) from $source; $active active."

    if ($findings.Count -eq 0) {
        Add-MtTestResultDetail -Result "Well done. No active GDAP relationship grants a highly privileged role for longer than $MaximumDays days. $summary"
        return $true
    }
    $table = "| Relationship | Customer | Why it is flagged |`n| --- | --- | --- |`n" + ((@($findings) | ForEach-Object { "| $($_.Relationship) | $($_.Customer) | $($_.Reason) |" }) -join "`n")
    Add-MtTestResultDetail -Result "$($findings.Count) relationship(s) grant standing high privilege. $summary`n`n$table"
    return $false
}
