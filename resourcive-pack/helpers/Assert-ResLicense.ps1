function Assert-ResLicense {
    <#
    .SYNOPSIS
    Skips the running test, with the reason, when the tenant is known not to hold a licence the test needs.

    .DESCRIPTION
    The engine already skips a test whose License attribute the tenant lacks. This is the second line, for a run
    that reached the test anyway (licence enforcement turned off, or licences that were unreadable when the run
    started). When the licences can be read and none of the service plans is present, the test is reported as
    Skipped with a reason that starts with "Not licensed:". When the licences cannot be read the test carries on,
    and a Graph 403 is turned into a skip by Resolve-ResGraphError.
    #>
    [CmdletBinding()]
    param(
        # The licence in words, for the skip reason, for example 'Microsoft Entra ID P2'.
        [Parameter(Mandatory)]
        [string] $Name,

        # Service plan names. The tenant needs any one of them.
        [Parameter(Mandatory)]
        [string[]] $ServicePlan
    )

    if ((Test-ResLicense -ServicePlan $ServicePlan) -eq $false) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason "Not licensed: this check needs $Name (service plan $($ServicePlan -join ' or ')), which the tenant does not have."
    }
}
