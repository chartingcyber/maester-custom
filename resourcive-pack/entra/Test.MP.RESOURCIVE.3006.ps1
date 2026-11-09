function Test-ResHibpPrivilegedExposure {
    <#
    .SYNOPSIS
    Checks Have I Been Pwned for breach and stealer log exposure of the verified domains, and joins it to the privileged users.

    .DESCRIPTION
    For each verified domain of the tenant, asks Have I Been Pwned (HIBP) which email aliases appear in data breaches
    (breachedDomain) and, with a Pro subscription, in infostealer logs (stealerLogsByEmailDomain). The aliases are
    joined to the users who hold privileged Entra roles. The check fails when a privileged user appears in either.
    The count of other exposed addresses is reported.

    This check sends your domain names to a third party (haveibeenpwned.com), so it does nothing until the
    ClientAuthorized parameter is set, to record that the organization has authorized it. Each domain must also be
    verified in the HIBP dashboard, and the API key must be set in the RESOURCIVE_HIBP_API_KEY environment variable.
    Domain search needs an HIBP Core or Pro subscription; stealer log search needs Pro. Addresses are masked in the
    result unless ShowAddresses is set.
    #>
    [MaesterTest(
        Id           = 'MP.RESOURCIVE.3006',
        Title        = 'No privileged user appears in Have I Been Pwned breach or stealer log data.',
        Product      = 'entra',
        Feature      = 'user-settings',
        Area         = 'authentication',
        ResourceType = 'User',
        Severity     = 'High',
        UserImpact   = 'Medium',
        ImplementationCost = 'Medium',
        Mitre        = ('T1078.004', 'T1555.003'),
        Control      = ('nist-800-53-r5:IA-5'),
        Service      = 'Graph',
        Permission   = ('Graph:Scope:Directory.Read.All', 'Graph:Scope:RoleManagement.Read.Directory')
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        # Confirms that the organization has authorized sending its domain names to Have I Been Pwned.
        [switch] $ClientAuthorized,

        # Show full email addresses in the result instead of masked ones.
        [switch] $ShowAddresses
    )

    if (-not $ClientAuthorized) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason 'Not assessed: this check sends the verified domain names to haveibeenpwned.com and needs the organization''s written authorization. Run it with the ClientAuthorized parameter set to true once that is recorded.'
    }
    $apiKey = [string]$env:RESOURCIVE_HIBP_API_KEY
    if ([string]::IsNullOrWhiteSpace($apiKey)) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason 'Not assessed: set the RESOURCIVE_HIBP_API_KEY environment variable to a Have I Been Pwned API key (Core or Pro subscription; Pro for stealer logs) whose subscription covers the verified domains.'
    }

    try {
        $domains = @(Invoke-MtGraphRequest -RelativeUri 'domains' -ApiVersion v1.0 -Select id, isVerified, isDefault, authenticationType -ErrorAction Stop | Where-Object { $_.isVerified -and $_.id -notmatch '\.onmicrosoft\.com$' })
        $privileged = @(Get-ResPrivilegedUser)
    } catch {
        Resolve-ResGraphError -ErrorRecord $_ -Feature 'verified domains and privileged users' -Requires 'Directory.Read.All and RoleManagement.Read.Directory'
    }
    if ($domains.Count -eq 0) {
        Add-MtTestResultDetail -SkippedBecause NotApplicable
    }

    $headers = @{ 'hibp-api-key' = $apiKey; 'user-agent' = 'resourcive-maester-pack' }
    function Get-DisplayAddress {
        param($Address)
        if ($ShowAddresses) { $Address } else { $Address -replace '^(.).*?@', '$1***@' }
    }

    $exposed = [System.Collections.Generic.List[object]]::new()
    $notes = [System.Collections.Generic.List[string]]::new()
    foreach ($domain in $domains) {
        foreach ($source in @(
                @{ Name = 'breach'; Path = "breachedDomain/$($domain.id)" }
                @{ Name = 'stealer log'; Path = "stealerLogsByEmailDomain/$($domain.id)" }
            )) {
            try {
                $response = Invoke-RestMethod -Uri "https://haveibeenpwned.com/api/v3/$($source.Path)" -Headers $headers -Method Get -ErrorAction Stop
                foreach ($property in $response.PSObject.Properties) {
                    $exposed.Add([pscustomobject]@{ Address = "$($property.Name)@$($domain.id)".ToLowerInvariant(); Source = $source.Name; Detail = (@($property.Value) -join ', ') })
                }
            } catch {
                $status = if ($_.Exception.PSObject.Properties['Response'] -and $_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
                switch ($status) {
                    404 { }
                    401 { $notes.Add("The Have I Been Pwned API key was refused (401) for $($domain.id)."); break }
                    403 { $notes.Add("$($domain.id): $($source.Name) search refused (403). The domain must be verified in the HIBP dashboard and the subscription must include this search."); break }
                    429 { $notes.Add("$($domain.id): $($source.Name) search was rate limited (429) and is not assessed."); break }
                    default { $notes.Add("$($domain.id): $($source.Name) search failed ($($_.Exception.Message))."); break }
                }
            }
        }
    }

    $privilegedAddresses = @{}
    foreach ($user in $privileged) {
        foreach ($address in @($user.UserPrincipalName, $user.Mail)) { if ($address) { $privilegedAddresses[([string]$address).ToLowerInvariant()] = $user } }
    }
    $privilegedHits = @($exposed | Where-Object { $privilegedAddresses.ContainsKey($_.Address) })
    $otherCount = @($exposed | Where-Object { -not $privilegedAddresses.ContainsKey($_.Address) } | Select-Object -ExpandProperty Address -Unique).Count

    $asOf = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm')
    $noteText = if ($notes.Count -gt 0) { "`n`nNot assessed: $($notes -join ' ')" } else { '' }
    $summary = "Searched $($domains.Count) verified domain(s) as of $asOf UTC. $otherCount other address(es) appear in HIBP data.$noteText"

    if ($privilegedHits.Count -eq 0) {
        if ($notes.Count -ge ($domains.Count * 2)) {
            Add-MtTestResultDetail -Result "Nothing could be assessed. $summary" -Investigate
            return $false
        }
        Add-MtTestResultDetail -Result "Well done. No privileged user appears in the HIBP data that could be searched. $summary"
        return $true
    }
    $table = "| User | Found in | Detail |`n| --- | --- | --- |`n" + ((@($privilegedHits) | ForEach-Object { "| $(Get-DisplayAddress -Address $_.Address) | $($_.Source) | $($_.Detail) |" }) -join "`n")
    Add-MtTestResultDetail -Result "$(@($privilegedHits | Select-Object -ExpandProperty Address -Unique).Count) privileged user(s) appear in HIBP data. $summary`n`n$table"
    return $false
}
