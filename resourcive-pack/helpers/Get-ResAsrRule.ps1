function Get-ResAsrRule {
    <#
    .SYNOPSIS
    Returns the attack surface reduction rules that Intune exposes in the settings catalog, with a friendly name and a purpose group.

    .DESCRIPTION
    Each rule's Key is the end of its settings catalog definition ID
    (device_vendor_msft_policy_config_defender_attacksurfacereductionrules_<Key>). Group is Script, Usb,
    Credential, Office, Email or General, so that a check can ask for the rules that block scripts or USB execution. Applicability is Required, ServerOnly (Webshell creation, which applies to Windows Server only) or Preview (rules Microsoft still lists as preview).
    The rule names are those of the Microsoft ASR rules reference.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    # Each rule is a one-element array wrapped by the leading comma, so that @() does not unroll the rows into one flat list.
    $rules = @(
        ,@('blockexecutionofpotentiallyobfuscatedscripts', 'Block execution of potentially obfuscated scripts', 'Script')
        ,@('blockjavascriptorvbscriptfromlaunchingdownloadedexecutablecontent', 'Block JavaScript or VBScript from launching downloaded executable content', 'Script')
        ,@('blockuntrustedunsignedprocessesthatrunfromusb', 'Block untrusted and unsigned processes that run from USB', 'Usb')
        ,@('blockcredentialstealingfromwindowslocalsecurityauthoritysubsystem', 'Block credential stealing from the Windows local security authority subsystem (LSASS)', 'Credential')
        ,@('blockabuseofexploitedvulnerablesigneddrivers', 'Block abuse of exploited vulnerable signed drivers', 'General')
        ,@('blockpersistencethroughwmieventsubscription', 'Block persistence through WMI event subscription', 'General')
        ,@('blockprocesscreationsfrompsexecandwmicommands', 'Block process creations originating from PSExec and WMI commands', 'General')
        ,@('blockuseofcopiedorimpersonatedsystemtools', 'Block use of copied or impersonated system tools', 'General')
        ,@('blockrebootingmachineinsafemode', 'Block rebooting machine in Safe Mode', 'General')
        ,@('useadvancedprotectionagainstransomware', 'Use advanced protection against ransomware', 'General')
        ,@('blockexecutablefilesrunningunlesstheymeetprevalenceagetrustedlistcriterion', 'Block executable files from running unless they meet a prevalence, age, or trusted list criterion', 'General')
        ,@('blockwebshellcreationforservers', 'Block Webshell creation for Servers', 'General')
        ,@('blockwin32apicallsfromofficemacros', 'Block Win32 API calls from Office macros', 'Office')
        ,@('blockofficecommunicationappfromcreatingchildprocesses', 'Block Office communication application from creating child processes', 'Office')
        ,@('blockallofficeapplicationsfromcreatingchildprocesses', 'Block all Office applications from creating child processes', 'Office')
        ,@('blockofficeapplicationsfromcreatingexecutablecontent', 'Block Office applications from creating executable content', 'Office')
        ,@('blockofficeapplicationsfrominjectingcodeintootherprocesses', 'Block Office applications from injecting code into other processes', 'Office')
        ,@('blockadobereaderfromcreatingchildprocesses', 'Block Adobe Reader from creating child processes', 'Office')
        ,@('blockexecutablecontentfromemailclientandwebmail', 'Block executable content from email client and webmail', 'Email')
    )

    # Rules that cannot or need not be required on a Windows client estate: one is for servers only, two are preview rules.
    $serverOnly = @('blockwebshellcreationforservers')
    $preview = @('blockuseofcopiedorimpersonatedsystemtools', 'blockrebootingmachineinsafemode')

    foreach ($rule in $rules) {
        $applicability = if ($rule[0] -in $serverOnly) { 'ServerOnly' } elseif ($rule[0] -in $preview) { 'Preview' } else { 'Required' }
        [pscustomobject]@{
            Key          = $rule[0]
            Name         = $rule[1]
            Group        = $rule[2]
            Applicability = $applicability
            DefinitionId = "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_$($rule[0])"
        }
    }
}
