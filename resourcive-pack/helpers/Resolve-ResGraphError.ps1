function Resolve-ResGraphError {
    <#
    .SYNOPSIS
    Turns a Graph error that means "not licensed" or "not permitted" into a skip, and rethrows any other error.

    .DESCRIPTION
    Call it from a catch block: catch { Resolve-ResGraphError -ErrorRecord $_ -Feature 'sign-in logs' }.
    A licence error (the tenant has no premium licence, or the feature is not available) becomes a skip whose
    reason starts with "Not licensed:". A 401 or 403 that is not a licence error becomes a skip whose reason
    starts with "Not authorized:" and names the permission or role to add. Anything else is thrown again, so the
    engine reports it as an Error.
    #>
    [CmdletBinding()]
    param(
        # The error record from the catch block.
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord] $ErrorRecord,

        # What was being read, in words, for the skip reason.
        [Parameter(Mandatory)]
        [string] $Feature,

        # The permission or role that is needed, shown in the reason when the error is an authorization error.
        [string] $Requires
    )

    $message = [string]$ErrorRecord.Exception.Message
    $details = [string]$ErrorRecord.ErrorDetails.Message
    $text = "$message $details"
    $status = $null
    if ($ErrorRecord.Exception.PSObject.Properties['Response'] -and $ErrorRecord.Exception.Response) {
        $status = [int]$ErrorRecord.Exception.Response.StatusCode
    }

    $licenceError = $text -match 'premium license|AadPremiumLicenseRequired|RequestFromNonPremiumTenantOrB2CTenant|not licensed|license is required|FeatureNotEnabled|tenant is not onboarded|does not have a valid license|no valid license'
    if ($licenceError) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason "Not licensed: $Feature is not available in this tenant ($($message.Split("`n")[0]))."
    }

    if ($status -in @(401, 403) -or $text -match 'Forbidden|Authorization_RequestDenied|Insufficient privileges|AccessDenied') {
        $needs = if ($Requires) { " Needs: $Requires." } else { '' }
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason "Not authorized: $Feature could not be read with the current permissions.$needs"
    }

    throw $ErrorRecord
}
