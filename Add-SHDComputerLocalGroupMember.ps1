function Add-SHDComputerLocalGroupMember {
    <#
    .SYNOPSIS
        Adds username to target group on target computer. 
    .DESCRIPTION
        Loops through a list of computers and adds a list of users inside a of computers on each computer. 
    .PARAMETER Computername
        [String[]] - List of target computers to search the groups and added users with. 
    .PARAMETER GroupName
        [String[]] - List of Groups to add users to.
    .PARAMETER Username
        [String[]] - List of Usernames to add to groups on target computer
    .PARAMETER Credential
        Optional credentials switch that allows you to use another credential.
    .EXAMPLE
        Add-SHDComputerLocalGroupMember -ComputerName <Server1>,<Server2>,<Server3> -GroupName "Remote Desktop Users","Users" -Username "User1","User2","User3"

        Adds User1, User2, and User3 to the remote desktop user group and the users group on server1, server2, server3 using the currently running credentials.
    .EXAMPLE
        Add-SHDComputerLocalGroupMember -ComputerName <Server1>,<Server2>,<Server3> -GroupName "Remote Desktop Users","Users" -Username "User1","User2","User3" -Credential (Get-Credential)

        Adds User1, User2, and User3 to the remote desktop user group and the users group on server1, server2, server3 using the credentials provided.
    .OUTPUTS
        System.Object
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
        [Parameter(HelpMessage = "Target Group", Mandatory = $True)][String[]]$GroupName,
        [Parameter(HelpMessage = "DomainName/Username", Mandatory = $True)][string[]]$username,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )
    $parameters = @{
        ComputerName = $ComputerName
        ScriptBlock  = {
            param($Param1, $Param2)
            foreach ($Group in $Param1) {
                foreach ($user in $Param2) {
                    Add-LocalGroupMember -Group $Group -Member $User -Confirm:$false
                }
                Get-LocalGroupMember -Group $Group | Select-Object @{L = "GroupName"; e = { $Group } }, Name
            }
        }         
        Argumentlist = $GroupName, $username
    }
    if ($PSBoundParameters.ContainsKey('Credential')) { $parameters += @{Credential = $Credential } }
    Invoke-Command @parameters
} #Review - Documentation






"Backup Operators", "Users"