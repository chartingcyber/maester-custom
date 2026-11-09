function Resolve-ResGroupMemberAddress {
    <#
    .SYNOPSIS
    Returns the lower-case addresses (user principal name and mail) of the user members of a group named in a protection policy rule.

    .DESCRIPTION
    A rule names a group by SMTP address, name, alias or ID. This finds the group in Microsoft Graph, reads its
    transitive user members, and returns every user principal name and mail address. Results are kept in the Cache
    hashtable so each group is read once per run. A group that cannot be found returns an empty list and is recorded
    in the cache under the key '__unresolved' so the caller can report it.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        # The identity as written in the rule.
        [Parameter(Mandatory)]
        [string] $Identity,

        # A hashtable shared by the caller, to avoid reading a group twice.
        [Parameter(Mandatory)]
        [hashtable] $Cache
    )

    $key = $Identity.ToLowerInvariant()
    if ($Cache.ContainsKey($key)) { return , $Cache[$key] }

    $escaped = $Identity.Replace("'", "''")
    $group = $null
    if ($Identity -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
        $group = Invoke-MtGraphRequest -RelativeUri "groups/$Identity" -ApiVersion v1.0 -Select id, displayName -ErrorAction SilentlyContinue
    } else {
        $filters = if ($Identity -match '@') {
            @("mail eq '$escaped'", "proxyAddresses/any(p:p eq 'smtp:$escaped')")
        } else {
            @("displayName eq '$escaped'", "mailNickname eq '$escaped'")
        }
        foreach ($filter in $filters) {
            $found = @(Invoke-MtGraphRequest -RelativeUri 'groups' -ApiVersion v1.0 -Filter $filter -Select id, displayName -ErrorAction SilentlyContinue)
            if ($found.Count -gt 0) { $group = $found[0]; break }
        }
    }

    $addresses = [System.Collections.Generic.List[string]]::new()
    if ($group) {
        $members = @(Invoke-MtGraphRequest -RelativeUri "groups/$($group.id)/transitiveMembers/microsoft.graph.user" -ApiVersion v1.0 -Select id, userPrincipalName, mail)
        foreach ($member in $members) {
            if ($member.userPrincipalName) { $addresses.Add(([string]$member.userPrincipalName).ToLowerInvariant()) }
            if ($member.mail) { $addresses.Add(([string]$member.mail).ToLowerInvariant()) }
        }
    } else {
        if (-not $Cache.ContainsKey('__unresolved')) { $Cache['__unresolved'] = [System.Collections.Generic.List[string]]::new() }
        $Cache['__unresolved'].Add($Identity)
    }

    $result = [string[]]@($addresses | Select-Object -Unique)
    $Cache[$key] = $result
    return , $result
}
