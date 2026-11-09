function Get-ResWindowsManagedDevice {
    <#
    .SYNOPSIS
    Returns the Windows devices managed by Intune with the fields the endpoint checks need.

    .DESCRIPTION
    Reads deviceManagement/managedDevices filtered to Windows and returns id, deviceName, userPrincipalName,
    azureADDeviceId, isEncrypted, complianceState, managementAgent, osVersion, lastSyncDateTime and ownership.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $select = 'id,deviceName,userPrincipalName,azureADDeviceId,isEncrypted,complianceState,managementAgent,operatingSystem,osVersion,lastSyncDateTime,managedDeviceOwnerType,deviceEnrollmentType'
    $uri = "deviceManagement/managedDevices?`$filter=operatingSystem eq 'Windows'&`$select=$select"
    @(Invoke-MtGraphRequest -RelativeUri $uri -ApiVersion beta)
}
