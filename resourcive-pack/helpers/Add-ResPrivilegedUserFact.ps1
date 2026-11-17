function Add-ResPrivilegedUserFact {
    <#
    .SYNOPSIS
    Adds what the pack knows about privileged users to the report's Affected objects page.

    .DESCRIPTION
    For each user, adds facts with Add-MtAffectedObjectFact: the privileged roles held (key user.privilegedRoles) split
    into active and eligible, what kind of account it is (guest, disabled, synced from on-premises), when it last signed
    in (key signIn.daysSince) when the activity record is given, and, when the authentication method registration
    record is given, whether MFA is registered (user.mfaRegistered),
    whether a passwordless method can be used (user.passwordless) and whether the user can complete MFA. A check adds
    its own finding as an extra fact. Facts only describe objects that a check names with
    Add-MtTestResultDetail -GraphObjects, so call this for the users the check names. The call does nothing in a run
    that does not collect affected objects.

    Facts with the same key from the same source replace each other, so every check can add the common facts for the
    same user without duplicating them.

    .EXAMPLE
    Add-ResPrivilegedUserFact -User $user -Registration $registration -Fact @{ Name = 'Phishing-resistant method'; Value = 'None'; Tone = 'Risk'; Key = 'resourcive.phishingResistant'; Raw = $false }
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        # A privileged user from Get-ResPrivilegedUser.
        [Parameter(Mandatory)]
        [pscustomobject] $User,

        # The user's record from reports/authenticationMethods/userRegistrationDetails, when it was read.
        [AllowNull()]
        [pscustomobject] $Registration,

        # The user's record from Get-ResUserActivity, when it was read.
        [AllowNull()]
        [pscustomobject] $Activity,

        # Facts the calling check adds for itself: hashtables with Name, Value, and optionally Tone, Key and Raw.
        [object[]] $Fact = @(),

        # When the data was read.
        [datetime] $AsOf = [datetime]::UtcNow
    )

    # A fact is kept by the user's id, so a user without one cannot be described.
    if (-not $User.Id) { return }

    $roles = @($User.Roles | Where-Object { $_ })
    $facts = [System.Collections.Generic.List[object]]::new()
    $facts.Add(@{
            Name  = 'Privileged roles'
            Value = if ($roles.Count -gt 0) { $roles -join ', ' } else { 'None' }
            Tone  = if ($roles.Count -ge 3) { 'Warning' } else { 'Info' }
            Key   = 'user.privilegedRoles'
            Raw   = @($roles)
        })
    $facts.Add(@{ Name = 'Active roles'; Value = $(if (@($User.ActiveRoles).Count -gt 0) { @($User.ActiveRoles) -join ', ' } else { 'None' }); Tone = 'Info'; Key = 'resourcive.activeRoles'; Raw = @($User.ActiveRoles | Where-Object { $_ }) })
    $facts.Add(@{ Name = 'Eligible roles'; Value = $(if (@($User.EligibleRoles).Count -gt 0) { @($User.EligibleRoles) -join ', ' } else { 'None' }); Tone = 'Info'; Key = 'resourcive.eligibleRoles'; Raw = @($User.EligibleRoles | Where-Object { $_ }) })
    $marks = [System.Collections.Generic.List[string]]::new()
    if ($User.UserType -eq 'Guest') { $marks.Add('Guest') }
    if ($User.AccountEnabled -eq $false) { $marks.Add('Disabled') }
    if ($User.OnPremisesSyncEnabled) { $marks.Add('Synced from on-premises') }
    $facts.Add(@{
            Name  = 'Account'
            Value = if ($marks.Count -gt 0) { $marks -join ', ' } else { 'Cloud-only member' }
            Tone  = if ($marks.Count -gt 0) { 'Warning' } else { 'Info' }
            Key   = 'resourcive.accountMarks'
            Raw   = @($marks)
        })
    if ($Activity) {
        if ($Activity.LastSignIn) {
            $days = [int][math]::Floor(($AsOf.ToUniversalTime() - ([datetime]$Activity.LastSignIn).ToUniversalTime()).TotalDays)
            $facts.Add(@{ Name = 'Last sign-in'; Value = "$($Activity.LastSignIn.ToString('yyyy-MM-dd')) ($days day(s) ago)"; Tone = $(if ($days -gt 90) { 'Warning' } else { 'Info' }); Key = 'signIn.daysSince'; Raw = $days })
        } else {
            $facts.Add(@{ Name = 'Last sign-in'; Value = 'No sign-in recorded'; Tone = 'Warning'; Key = 'signIn.daysSince'; Raw = $null })
        }
        if ($Activity.LastPasswordChange) {
            $age = [int][math]::Floor(($AsOf.ToUniversalTime() - ([datetime]$Activity.LastPasswordChange).ToUniversalTime()).TotalDays)
            $facts.Add(@{ Name = 'Password last changed'; Value = "$age day(s) ago"; Tone = 'Info'; Key = 'resourcive.passwordAgeDays'; Raw = $age })
        }
    }
    if ($Registration) {
        $facts.Add(@{
                Name  = 'MFA registered'
                Value = if ($Registration.isMfaRegistered) { 'Yes' } else { 'No' }
                Tone  = if ($Registration.isMfaRegistered) { 'Good' } else { 'Risk' }
                Key   = 'user.mfaRegistered'
                Raw   = [bool]$Registration.isMfaRegistered
            })
        $facts.Add(@{
                Name  = 'MFA capable'
                Value = if ($Registration.isMfaCapable) { 'Yes' } else { 'No' }
                Tone  = if ($Registration.isMfaCapable) { 'Good' } else { 'Risk' }
                Key   = 'resourcive.mfaCapable'
                Raw   = [bool]$Registration.isMfaCapable
            })
        $facts.Add(@{
                Name  = 'Passwordless capable'
                Value = if ($Registration.isPasswordlessCapable) { 'Yes' } else { 'No' }
                Tone  = 'Info'
                Key   = 'user.passwordless'
                Raw   = [bool]$Registration.isPasswordlessCapable
            })
    }
    foreach ($item in @($Fact)) { if ($item) { $facts.Add($item) } }

    Add-MtAffectedObjectFact -Type User -Id ([string]$User.Id) -Source 'Resourcive M365 Assessment' -AsOf $AsOf -Fact $facts.ToArray()
}
