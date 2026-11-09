function Get-ResCaGroupMemberId {
    <#
    .SYNOPSIS
    Returns the object IDs of the users who are members of each group, including nested members.

    .DESCRIPTION
    Reads groups/{id}/transitiveMembers/microsoft.graph.user for each group ID and returns a hashtable of group ID
    to member ID list. A group that cannot be read (deleted, or outside the tenant) maps to an empty list and a
    warning is recorded in Failed. Reads go through Invoke-MtGraphRequest, which caches them for the run.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        # Group object IDs.
        [AllowEmptyCollection()]
        [string[]] $GroupId = @()
    )

    $map = @{}
    $failed = [System.Collections.Generic.List[string]]::new()
    foreach ($id in ($GroupId | Where-Object { $_ } | Select-Object -Unique)) {
        try {
            $map[$id] = @(Invoke-MtGraphRequest -RelativeUri "groups/$id/transitiveMembers/microsoft.graph.user" -ApiVersion v1.0 -Select id -ErrorAction Stop | ForEach-Object { [string]$_.id })
        } catch {
            $map[$id] = @()
            $failed.Add("$id ($($_.Exception.Message.Split("`n")[0]))")
        }
    }
    $map['__failed'] = $failed.ToArray()
    $map
}
