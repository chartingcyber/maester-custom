function Get-ResUserActivity {
    <#
    .SYNOPSIS
    Reads when each user last signed in and last changed their password.

    .DESCRIPTION
    Reads signInActivity, lastPasswordChangeDateTime and createdDateTime of each user by ID. signInActivity needs
    Entra ID P1 and the AuditLog.Read.All permission. A user that cannot be read is left out of the result, so the
    caller shows no fact for them rather than a guess. LastSignIn is the most recent of the interactive and
    non-interactive sign-ins and is $null when no sign-in has been recorded.

    Returns a hashtable of user ID to an object with LastSignIn, LastPasswordChange and Created (UTC datetimes or $null).
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        # User object IDs.
        [AllowEmptyCollection()]
        [string[]] $UserId = @()
    )

    $map = @{}
    foreach ($id in ($UserId | Where-Object { $_ } | Select-Object -Unique)) {
        try {
            $user = Invoke-MtGraphRequest -RelativeUri "users/$id" -ApiVersion beta -Select id, signInActivity, lastPasswordChangeDateTime, createdDateTime -ErrorAction Stop
        } catch { continue }
        if (-not $user) { continue }
        $signIns = @($user.signInActivity.lastSignInDateTime, $user.signInActivity.lastNonInteractiveSignInDateTime |
                Where-Object { $_ } | ForEach-Object { ([datetime]$_).ToUniversalTime() })
        $map[$id] = [pscustomobject]@{
            LastSignIn         = if ($signIns.Count -gt 0) { ($signIns | Sort-Object -Descending)[0] } else { $null }
            LastPasswordChange = if ($user.lastPasswordChangeDateTime) { ([datetime]$user.lastPasswordChangeDateTime).ToUniversalTime() } else { $null }
            Created            = if ($user.createdDateTime) { ([datetime]$user.createdDateTime).ToUniversalTime() } else { $null }
        }
    }
    $map
}
