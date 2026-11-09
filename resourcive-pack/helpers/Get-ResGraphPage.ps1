function Get-ResGraphPage {
    <#
    .SYNOPSIS
    Turns the result of Invoke-MtGraphRequest -DisablePaging into its rows.

    .DESCRIPTION
    With -DisablePaging, Invoke-MtGraphRequest returns the raw Graph response, an object with a value array and
    perhaps an @odata.nextLink, instead of the rows. This function unwraps it. A response that has no value
    property (a single object) is returned as one row. HasMore is true when Graph says there are more rows than
    the page that was read.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        # The output of Invoke-MtGraphRequest -DisablePaging.
        [AllowNull()]
        $Response
    )

    $items = @($Response | Where-Object { $null -ne $_ })
    $rows = [System.Collections.Generic.List[object]]::new()
    $hasMore = $false
    foreach ($item in $items) {
        $isMap = $item -is [System.Collections.IDictionary]
        $hasValue = if ($isMap) { $item.Contains('value') } else { $null -ne $item.PSObject.Properties['value'] }
        if ($hasValue) {
            $value = if ($isMap) { $item['value'] } else { $item.value }
            foreach ($row in @($value | Where-Object { $null -ne $_ })) { $rows.Add($row) }
            $next = if ($isMap) { $item['@odata.nextLink'] } else { $item.PSObject.Properties['@odata.nextLink'].Value }
            if ($next) { $hasMore = $true }
        } else {
            $rows.Add($item)
        }
    }
    [pscustomobject]@{ Rows = @($rows); HasMore = $hasMore }
}
