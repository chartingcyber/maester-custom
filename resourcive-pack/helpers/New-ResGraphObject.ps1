function New-ResGraphObject {
    <#
    .SYNOPSIS
    Builds the object that Add-MtTestResultDetail -GraphObjects needs to name something on the Affected objects page.

    .DESCRIPTION
    Returns an object with id, displayName, userPrincipalName and @odata.type. A check passes a mix of these without a
    -GraphObjectType, so Maester reads each object's type from its @odata.type: users, devices and groups get the
    portal links Maester knows, and service principals and Conditional Access policies are recorded under their own
    types. Add-MtAffectedObjectFact then attaches facts to the same objects.

    .EXAMPLE
    New-ResGraphObject -Type User -Id $user.Id -DisplayName $user.DisplayName -UserPrincipalName $user.UserPrincipalName
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        # The kind of object.
        [Parameter(Mandatory)]
        [ValidateSet('User', 'Device', 'Group', 'ServicePrincipal', 'ConditionalAccessPolicy')]
        [string] $Type,

        # The object's directory ID.
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Id,

        # The name to show.
        [string] $DisplayName,

        # The user principal name, for a user.
        [string] $UserPrincipalName
    )

    $odata = switch ($Type) {
        'User' { '#microsoft.graph.user' }
        'Device' { '#microsoft.graph.device' }
        'Group' { '#microsoft.graph.group' }
        'ServicePrincipal' { '#microsoft.graph.servicePrincipal' }
        'ConditionalAccessPolicy' { '#microsoft.graph.conditionalAccessPolicy' }
    }
    [pscustomobject]@{
        'id'                = $Id
        'displayName'       = $DisplayName
        'userPrincipalName' = $UserPrincipalName
        '@odata.type'       = $odata
    }
}
