function Get-ResControlStatus {
    <#
    .SYNOPSIS
    Decides the status of an endpoint control from the policies that set it and who they reach.

    .DESCRIPTION
    Each piece of evidence says one policy sets the control, in what mode (Enforced or Audit) and to whom it is
    assigned. The status is:
    - Enforced: an enforcing policy reaches all devices or all users with no exclusion or filter.
    - Partial scope: an enforcing policy exists but reaches only groups, or an all-devices policy has exclusions.
    - Audit-only: policies exist but none enforces.
    - Not assigned: a policy sets the control but is assigned to nobody.
    - Not configured: no policy sets the control.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        # Evidence objects with Policy (name), Mode (Enforced or Audit) and Assignment (ConvertTo-ResAssignmentSummary).
        [AllowNull()]
        [object[]] $Evidence
    )

    $items = @($Evidence | Where-Object { $_ })
    if ($items.Count -eq 0) {
        return [pscustomobject]@{ Status = 'Not configured'; Detail = 'No policy sets this control.'; Enforcing = @(); Evidence = @() }
    }

    $assigned = @($items | Where-Object { $_.Assignment.Scope -ne 'None' })
    if ($assigned.Count -eq 0) {
        return [pscustomobject]@{ Status = 'Not assigned'; Detail = 'Policies set this control but none is assigned.'; Enforcing = @(); Evidence = $items }
    }

    $enforcing = @($assigned | Where-Object { $_.Mode -eq 'Enforced' })
    if ($enforcing.Count -eq 0) {
        return [pscustomobject]@{ Status = 'Audit-only'; Detail = 'Assigned policies audit or log but do not enforce.'; Enforcing = @(); Evidence = $items }
    }

    $everyone = @($enforcing | Where-Object { $_.Assignment.Scope -in @('AllDevices', 'AllUsers') -and -not $_.Assignment.HasExclusions })
    if ($everyone.Count -gt 0) {
        return [pscustomobject]@{ Status = 'Enforced'; Detail = "Enforced for all devices or users by: $((@($everyone | ForEach-Object { $_.Policy }) -join ', '))."; Enforcing = $enforcing; Evidence = $items }
    }

    [pscustomobject]@{
        Status    = 'Partial scope'
        Detail    = "Enforced only for part of the tenant by: $((@($enforcing | ForEach-Object { "$($_.Policy) ($($_.Assignment.Text))" }) -join '; ')). Confirm that the assigned groups cover every in-scope Windows device."
        Enforcing = $enforcing
        Evidence  = $items
    }
}
