function Get-ResPrivilegedUserNote {
    <#
    .SYNOPSIS
    Returns the caveats to print under a result built from Get-ResPrivilegedUser, or an empty string.

    .DESCRIPTION
    Says when eligible (PIM) assignments could not be read and when the members of a role-holding group could not be
    read, so a result never looks more complete than it is.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        # Output of Get-ResPrivilegedUser.
        [AllowEmptyCollection()] [object[]] $User = @()
    )
    if ($User.Count -eq 0) { return '' }
    $note = ''
    if (-not $User[0].EligibleReadable) { $note += ' Eligible (PIM) role assignments could not be read (Entra ID P2 not available), so only active role holders were evaluated.' }
    if (@($User[0].UnreadableGroups).Count -gt 0) { $note += " The members of $(@($User[0].UnreadableGroups).Count) group(s) that hold a privileged role could not be read and are not included: $(@($User[0].UnreadableGroups) -join '; ')." }
    $note
}
