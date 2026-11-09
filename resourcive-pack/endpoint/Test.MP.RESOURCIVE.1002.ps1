function Test-ResIntuneLapsAssigned {
    <#
    .SYNOPSIS
    Checks that an Intune Windows LAPS policy backs up the local administrator password, rotates it, and is assigned to every Windows device.

    .DESCRIPTION
    MT.1177 checks that a LAPS policy exists with a strong configuration. This check looks at who the policy reaches.
    It reads every settings catalog policy that sets the LAPS backup directory, treats a policy as enforcing when the
    directory is Entra ID or Active Directory, and reports whether an enforcing policy reaches all devices or all
    users without exclusions, only some groups, or nobody. It also checks that the password age is no longer than
    MaximumPasswordAgeDays.
    #>
    [MaesterTest(
        Id           = 'MP.RESOURCIVE.1002',
        Title        = 'A Windows LAPS policy is assigned to all Windows devices and rotates the password.',
        Product      = 'intune',
        RelatedProduct = 'entra',
        Feature      = 'endpoint-security',
        Area         = 'privileged-access',
        ResourceType = 'Tenant',
        Severity     = 'Medium',
        UserImpact   = 'Low',
        ImplementationCost = 'Medium',
        Mitre        = ('T1078.003', 'T1550.002'),
        Control      = 'nist-800-53-r5:IA-5',
        Service      = 'Graph',
        License      = 'INTUNE_A',
        Permission   = 'Graph:Scope:DeviceManagementConfiguration.Read.All'
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        # The longest password age, in days, that the policy may allow.
        [ValidateRange(1, 365)]
        [int] $MaximumPasswordAgeDays = 30
    )

    Assert-ResLicense -Name 'Microsoft Intune Plan 1' -ServicePlan (Get-ResServicePlanName -Product Intune)

    try {
        $policies = @(Get-ResIntuneConfigurationPolicy -DefinitionIdPattern '^device_vendor_msft_laps_policies_backupdirectory')
    } catch {
        Resolve-ResGraphError -ErrorRecord $_ -Feature 'Intune configuration policies' -Requires 'DeviceManagementConfiguration.Read.All'
    }

    $evidence = foreach ($policy in $policies) {
        $backup = $policy.Settings | Where-Object { $_.DefinitionId -eq 'device_vendor_msft_laps_policies_backupdirectory' } | Select-Object -First 1
        $directory = switch -Wildcard ([string]$backup.Value) {
            '*_1' { 'Entra ID' }
            '*_2' { 'Active Directory' }
            default { 'Disabled' }
        }
        $age = $policy.Settings | Where-Object { $_.DefinitionId -eq 'device_vendor_msft_laps_policies_passwordagedays' -or $_.DefinitionId -like 'device_vendor_msft_laps_policies_passwordagedays*' } | Select-Object -First 1
        $ageDays = if ($age -and $age.Value -match '^\d+$') { [int]$age.Value } else { $null }
        # A policy that sets no age uses the Windows LAPS default of 30 days. It is enforcing when it backs up the
        # password and the age it sets, or that default, is no longer than the limit.
        $effectiveAge = if ($null -ne $ageDays) { $ageDays } else { 30 }
        $enforcing = $directory -ne 'Disabled' -and $effectiveAge -le $MaximumPasswordAgeDays
        [pscustomobject]@{
            Policy     = $policy.Name
            Mode       = if ($enforcing) { 'Enforced' } else { 'Audit' }
            Assignment = $policy.Assignment
            Directory  = $directory
            AgeDays    = $ageDays
        }
    }

    $status = Get-ResControlStatus -Evidence @($evidence)

    $table = "| Policy | Backs up to | Password age (days) | Assigned to |`n| --- | --- | --- | --- |`n"
    foreach ($row in @($evidence)) {
        $table += "| $($row.Policy) | $($row.Directory) | $(if ($null -eq $row.AgeDays) { 'not set (Windows default: 30)' } else { $row.AgeDays }) | $($row.Assignment.Text) |`n"
    }
    if (@($evidence | Where-Object { $_ }).Count -eq 0) { $table = '' }

    $summary = "**Status: $($status.Status).** $($status.Detail)`n`nRequired: a policy that backs up the password and keeps the password age at $MaximumPasswordAgeDays days or less (a policy that sets no age uses the Windows LAPS default of 30 days), assigned to all devices or all users without exclusions.`n`n$table"

    switch ($status.Status) {
        'Enforced' {
            Add-MtTestResultDetail -Result "Well done. A Windows LAPS policy reaches all devices.`n`n$summary"
            return $true
        }
        'Partial scope' {
            Add-MtTestResultDetail -Result $summary -Investigate
            return $false
        }
        default {
            Add-MtTestResultDetail -Result $summary
            return $false
        }
    }
}
