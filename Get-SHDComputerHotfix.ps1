function Get-SHDComputerHotfix {
    <#
    .SYNOPSIS
        Gets target computers hot fix information.
    .DESCRIPTION
        Gets target computers hot fix information.
    .PARAMETER ComputerName
        Mandatory list of string that target a computer.
    .PARAMETER Credential
        Optional credentials.
    .EXAMPLE
        PS C:\Users\dbolding_adm> Get-SHDComputerHotfix -Computername Computer1


        Source        Description      HotFixID      InstalledBy          InstalledOn                PSComputerName
        ------        -----------      --------      -----------          -----------                --------------
                      Update           KB4578974     NT AUTHORITY\SYSTEM  10/14/2020 12:00:00 AM       Computer1
    .INPUTS
        List of String
    .OUTPUTS
        PScustomobject
    .NOTES
        Author: David Bolding
        Date: 10/15/2020
    .LINK
        https://github.com/rndadhdman/PS_Super_Helpdesk
    #>
    [cmdletbinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Provide the target hostname",
            Mandatory = $true)][Alias('Hostname', 'cn')][String[]]$Computername,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )
    foreach ($computer in $Computername) {
        if (Test-Connection -ComputerName $computer -Count 1 -Quiet) {
            try {
                if ($PSBoundParameters.ContainsKey('Credential')) {
                    $CIMSession = New-CimSession -ComputerName $Computer -Credential $Credential
                    Get-CimInstance -ClassName Win32_QuickFixEngineering -CimSession $CIMSession
                    Remove-CimSession $CIMSession
                }
                else {
                    Get-CimInstance -ClassName Win32_QuickFixEngineering -ComputerName $computer
                }
            }
            catch {
                try {
                    if ($PSBoundParameters.ContainsKey('Credential')) {
                        Get-WmiObject -Class Win32_QuickFixEngineering -ComputerName $Computer -Credential $Credential
                    }
                    else {
                        Get-WmiObject -Class Win32_QuickFixEngineering -computername $computer
                    }
                }
                catch {
                    Write-Warning "Unable to capture Data from $Computer."
                }
            }
        }
        else {
            Write-Warning "$Computer is offline."
        }
    }

} #Review - Testing, Documentation