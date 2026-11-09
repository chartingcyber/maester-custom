function Get-ResCaIpFromCidr {
    <#
    .SYNOPSIS
    Returns one usable IPv4 address from a CIDR range, or $null for anything that is not IPv4 CIDR.

    .DESCRIPTION
    Used to pick an address inside a trusted IP named location for the What If scenarios. For a /32 it is the
    address itself; otherwise the first host address of the range.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        # The range in CIDR notation, for example 203.0.113.0/24.
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Cidr
    )

    if ($Cidr -notmatch '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/(\d{1,2})$') { return $null }
    $octets = @([int]$Matches[1], [int]$Matches[2], [int]$Matches[3], [int]$Matches[4])
    $prefix = [int]$Matches[5]
    if (($octets | Where-Object { $_ -gt 255 }) -or $prefix -gt 32) { return $null }

    $address = [uint32](([uint32]$octets[0] -shl 24) -bor ([uint32]$octets[1] -shl 16) -bor ([uint32]$octets[2] -shl 8) -bor [uint32]$octets[3])
    $mask = if ($prefix -eq 0) { [uint32]0 } else { [uint32]([uint32]::MaxValue -shl (32 - $prefix)) }
    $network = $address -band $mask
    $host1 = if ($prefix -ge 31) { $network } else { $network + 1 }
    '{0}.{1}.{2}.{3}' -f (($host1 -shr 24) -band 255), (($host1 -shr 16) -band 255), (($host1 -shr 8) -band 255), ($host1 -band 255)
}
