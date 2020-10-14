function Clear-SHDComputerUserTemporaryFiles {
    <#
    .SYNOPSIS
        Clears out the users temporay files.
    .DESCRIPTION
        Clears out the users temporary files on target computer.
    .PARAMETER Computername
        [String[]] - Target Computer
    .PARAMETER Username
        [String[]] - Target user who's temporary files will be cleared.
    .PARAMETER Credential
        Optional credentials switch that allows you to use another credential.
    .EXAMPLE
        Clear-SHDComputerUserTemporaryFiles -ComputerName <Computer1>,<computer2> -Username <user1>,<user2> -Credential (Get-Credential)

        Clears all temp files from user1 and user2 from computer 1 and Computer2 using input credentials.
    .EXAMPLE
        Clear-SHDComputerUserTemporaryFiles -ComputerName <Computer1>,<computer2> -Username <user1>,<user2>

        Clears all temp files from user1 and user2 from computer 1 and Computer2 using your running credentials
    .OUTPUTS
        [None]
    .NOTES
        Author: David Bolding

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
        [Parameter(HelpMessage = "Target Username", Mandatory = $True)][String[]]$Username,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )
    $parameters = @{
        ComputerName = $ComputerName
        ScriptBlock  = {
            param ($Param1)
            foreach ($User in $Param1) {
                Remove-Item "C:\Users\$User\AppData\Local\Temp\*" -Recurse -Force -Verbose -ErrorAction SilentlyContinue -Confirm:$false
            }
        }
        Argumentlist = $Username
    }
    if ($PSBoundParameters.ContainsKey('Credential')) { $parameters += @{Credential = $Credential } }
    Invoke-Command @parameters
} #Review - Testing, Documentation