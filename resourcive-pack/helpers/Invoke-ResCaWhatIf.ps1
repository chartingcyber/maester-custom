function Invoke-ResCaWhatIf {
    <#
    .SYNOPSIS
    Runs one scenario through the Conditional Access What If API, with a cache, a throttle and a retry on transient errors.

    .DESCRIPTION
    Calls Test-MtConditionalAccessWhatIf with -AllResults, so the result carries the state and analysisReasons of
    every policy, and with every condition set explicitly (client app type, platform, country, IP address, risk).
    Results are cached by scenario key in the hashtable passed in, so a repeated scenario costs no call. HTTP 429,
    500, 502, 503 and 504 and timeouts are retried with a growing delay, up to four attempts. When the attempts
    are used up the function does not throw: it returns one row that carries resCaError (the reason), which
    Get-ResCaOutcome classifies as NotAssessed and the test shows as Investigate. That row is not cached. Other
    errors (permission, licence) are thrown.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        # The scenario from New-ResCaScenario.
        [Parameter(Mandatory)]
        $Scenario,

        # A hashtable that holds results by scenario key. Pass the same one to every call.
        [Parameter(Mandatory)]
        [hashtable] $Cache,

        # Wait this long before each call that is not served from the cache, in milliseconds.
        [ValidateRange(0, 60000)]
        [int] $ThrottleMilliseconds = 250
    )

    if ($Cache.ContainsKey($Scenario.Key)) { return , @($Cache[$Scenario.Key]) }

    $splat = @{
        UserId          = $Scenario.Persona.UserId
        ClientAppType   = $Scenario.ClientAppType
        DevicePlatform  = $Scenario.DevicePlatform
        SignInRiskLevel = $Scenario.SignInRiskLevel
        UserRiskLevel   = $Scenario.UserRiskLevel
        AllResults      = $true
    }
    if ($Scenario.Country) { $splat.Country = $Scenario.Country }
    if ($Scenario.IpAddress) { $splat.IpAddress = $Scenario.IpAddress }
    if ($Scenario.UserAction) { $splat.UserAction = $Scenario.UserAction } else { $splat.IncludeApplications = $Scenario.App.Id }

    $maxAttempts = 4
    $attempt = 0
    while ($true) {
        $attempt++
        if ($ThrottleMilliseconds -gt 0) { Start-Sleep -Milliseconds $ThrottleMilliseconds }
        try {
            $rows = @(Test-MtConditionalAccessWhatIf @splat)
            break
        } catch {
            $text = "$($_.Exception.Message) $($_.ErrorDetails.Message)"
            $transient = $text -match '\b(429|500|502|503|504)\b|TooManyRequests|throttl|InternalServerError|BadGateway|ServiceUnavailable|GatewayTimeout|Timeout|timed out'
            if (-not $transient) { throw }
            if ($attempt -ge $maxAttempts) {
                $reason = ($text.Trim() -split "`n")[0]
                if ($reason.Length -gt 200) { $reason = $reason.Substring(0, 200) }
                $failed = [pscustomobject]@{
                    id              = 'whatif-call-failed'
                    displayName     = 'What If call'
                    state           = 'enabled'
                    policyApplies   = $false
                    analysisReasons = 'notEnoughInformation'
                    grantControls   = $null
                    resCaError      = "HTTP or timeout error after $attempt attempts: $reason"
                }
                return , @($failed)
            }
            Start-Sleep -Milliseconds ($ThrottleMilliseconds + (2000 * $attempt))
        }
    }
    $Cache[$Scenario.Key] = $rows
    , $rows
}
