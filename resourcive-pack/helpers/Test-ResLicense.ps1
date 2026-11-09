function Test-ResLicense {
    <#
    .SYNOPSIS
    Tells whether the tenant has at least one of the named service plans.

    .DESCRIPTION
    Returns $true when one of the service plans is licensed, $false when the licences were read and none match,
    and $null when the licences could not be read (unknown). Names are Microsoft service plan names such as
    AAD_PREMIUM_P2, as in the Microsoft Learn list "Product names and service plan identifiers for licensing".
    #>
    [CmdletBinding()]
    [OutputType([System.Nullable[bool]])]
    param(
        # Service plan names. The tenant needs any one of them.
        [Parameter(Mandatory)]
        [string[]] $ServicePlan
    )

    $licensed = Get-ResLicensedServicePlan
    if ($null -eq $licensed) { return $null }
    foreach ($plan in $ServicePlan) {
        if ($licensed -contains $plan) { return $true }
    }
    return $false
}
