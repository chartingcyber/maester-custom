function Add-ResDeviceFact {
    <#
    .SYNOPSIS
    Adds what the pack knows about a device to the report's Affected objects page.

    .DESCRIPTION
    Adds facts with Add-MtAffectedObjectFact for one Entra device object, using the shared fact keys: device.managed,
    device.compliant, device.os, device.joinType and signIn.daysSince, plus the calling check's own facts. A value that
    is not known (null) adds no fact. The device is the Entra device object ID, the same ID that
    Add-MtTestResultDetail -GraphObjects records for it. The call does nothing in a run that does not collect
    affected objects.

    .EXAMPLE
    Add-ResDeviceFact -Id $device.id -OperatingSystem 'Windows' -Managed $false -Fact @{ Name = 'BitLocker'; Value = 'Not encrypted'; Tone = 'Risk' }
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        # The Entra device object ID.
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Id,

        [AllowNull()] [string] $OperatingSystem,

        # AzureAd, ServerAd or Workplace (Entra's trustType).
        [AllowNull()] [string] $JoinType,

        [AllowNull()] [object] $Managed,

        [AllowNull()] [object] $Compliant,

        # When the device last signed in or synced, to show how long ago.
        [AllowNull()] [object] $LastSeen,

        # Facts the calling check adds for itself.
        [object[]] $Fact = @(),

        [datetime] $AsOf = [datetime]::UtcNow
    )

    $facts = [System.Collections.Generic.List[object]]::new()
    if ($OperatingSystem) { $facts.Add(@{ Name = 'Operating system'; Value = $OperatingSystem; Tone = 'Info'; Key = 'device.os'; Raw = $OperatingSystem }) }
    if ($JoinType) {
        $joinText = switch ($JoinType) { 'AzureAd' { 'Entra joined' } 'ServerAd' { 'Hybrid joined' } 'Workplace' { 'Registered' } default { $JoinType } }
        $facts.Add(@{ Name = 'Join type'; Value = $joinText; Tone = 'Info'; Key = 'device.joinType'; Raw = $JoinType })
    }
    if ($null -ne $Managed) { $facts.Add(@{ Name = 'Managed'; Value = $(if ($Managed) { 'Yes' } else { 'No' }); Tone = $(if ($Managed) { 'Good' } else { 'Risk' }); Key = 'device.managed'; Raw = [bool]$Managed }) }
    if ($null -ne $Compliant) { $facts.Add(@{ Name = 'Compliant'; Value = $(if ($Compliant) { 'Yes' } else { 'No' }); Tone = $(if ($Compliant) { 'Good' } else { 'Warning' }); Key = 'device.compliant'; Raw = [bool]$Compliant }) }
    if ($LastSeen) {
        $days = [int][math]::Floor(($AsOf.ToUniversalTime() - ([datetime]$LastSeen).ToUniversalTime()).TotalDays)
        $facts.Add(@{ Name = 'Last seen'; Value = "$days day(s) ago"; Tone = $(if ($days -gt 90) { 'Warning' } else { 'Info' }); Key = 'signIn.daysSince'; Raw = $days })
    }
    foreach ($item in @($Fact)) { if ($item) { $facts.Add($item) } }
    if ($facts.Count -eq 0) { return }
    Add-MtAffectedObjectFact -Type Device -Id $Id -Source 'Resourcive M365 Assessment' -AsOf $AsOf -Fact $facts.ToArray()
}
