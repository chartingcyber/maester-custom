function Get-ResLicensedServicePlan {
    <#
    .SYNOPSIS
    Returns the names of the service plans the tenant has, or $null when they cannot be read.

    .DESCRIPTION
    Reads subscribedSkus and returns the service plan names of every SKU that is Enabled and whose plan is
    provisioned successfully. Returns $null (unknown) when the read fails, so that a caller can run on a best
    effort basis instead of guessing that the tenant is unlicensed.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    try {
        $skus = @(Invoke-MtGraphRequest -RelativeUri 'subscribedSkus' -ApiVersion v1.0 -ErrorAction Stop)
    } catch {
        Write-Verbose "Licences could not be read: $($_.Exception.Message)"
        return $null
    }

    $names = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($sku in $skus) {
        if ($sku.capabilityStatus -ne 'Enabled') { continue }
        foreach ($plan in @($sku.servicePlans)) {
            if ($plan.provisioningStatus -in @('Success', 'PendingInput', 'PendingProvisioning')) {
                $null = $names.Add([string]$plan.servicePlanName)
            }
        }
    }
    return , [string[]]@($names)
}
