function Get-SHDComputerCurrentUser {
    <#
    .SYNOPSIS
        Grabs the current users on target computer.
    .DESCRIPTION
        Grabs the current users from the target computer. You can filter out the active verse disconnected users, how long a user has been idle, and the username. All the while using the credentials of a different account.
    .PARAMETER ComputerName
        A mandatory list of strings parameter that can accept values from a pipeline. A list of computer names to target for this command.
    .PARAMETER State
        An optional string parameter. Either Active or Disc. Active finds all active users while Disc finds all Disconnected users.
    .PARAMETER IdleTimeGreaterThan
        An optional integer parameter. How many minutes a user has been idle past this these number of minutes.
    .PARAMETER Username
        An optional string parameter. Target's a single username.
    .PARAMETER Credentialdis
        An optional System Managment automation pscredential parameter. With this added, you will run the command with the given parameters. Without it, you will run the command with current running credentials.
    .EXAMPLE
        Get-SHDComputerCurrentUser -ComputerName Server1,Server2

        Gives all the current users of server1 and server2
    .EXAMPLE
        Get-SHDComputerCurrentUser -ComputerName Server1 -state Disc

        Gives all the disconnected users who are logged into server1
    .EXAMPLE
        Get-SHDComputerCurrentUser -ComputerName (Get-adcomputer -filter {name -like "pc*"}).name -Username

        This will tell you if username is logged into any of the computers witht he name like pc*.
    .EXAMPLE
        Get-SHDComputerCurrentUser -ComputerName Server1 -Idletimegreaterthan 30

        This will give all the current users on server 1 who has been logged in for more than 30 minutes.
    .INPUTS
        List of Strings
    .OUTPUTS
        PS Custom Object
    .NOTES
        Author: David Bolding
        Date: 10/14/2020
        
    .LINK
    #>
    [cmdletbinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Provide the target hostname",
            Mandatory = $true)][Alias('Hostname', 'cn')][String[]]$Computername,
        [Parameter(Helpmessage = "Search By State")][validateset("Active","Disc")][string]$State,
        [Parameter(HelpMessage = "Idle time greater")][int]$IdleTimeGreaterThan,
        [Parameter(HelpMessage = "Search For Username")][String]$Username,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )
    $parameters = @{
        ComputerName = $ComputerName
        ScriptBlock  = {
            $Test = (((quser /server:"$($env:COMPUTERNAME)" 2> $null) -replace '^>', '') -replace '\s{2,}', ',') | ForEach-Object {
                if ($_.Split(',').Count -eq 5) {
                    Write-Output ($_ -replace '(^[^,]+)', '$1,')
                }
                else {
                    Write-Output $_
                }
            } | ConvertFrom-Csv
            $Test | Where-Object { $_."IDLE TIME" -like "." } | ForEach-Object { $_."IDLE TIME" = $null }
            $Test | ForEach-Object { $_."IDLE TIME" = [int]$_."IDLE TIME" }
            $Test
        }
    }
    if ($PSBoundParameters.ContainsKey('Credential')) { $parameters += @{Credential = $Credential } }
    $Info = Invoke-Command @parameters | Sort-Object pscomputername | Select-Object pscomputername,USERNAME,SESSIONNAME,ID,STATE,"IDLE TIME","lOGON tIME"
    if ($PSBoundParameters.ContainsKey('State')) {$Info = $Info | Where-Object {$_.STATE -like "*$State*"}}
    if ($PSBoundParameters.ContainsKey('IdleTimeGreaterThan')) {$Info = $Info | Where-Object {$_."IDLE TIME" -ge $IdleTimeGreaterThan}}
    if ($PSBoundParameters.ContainsKey('Username')) {$Info = $Info | Where-Object {$_.USERNAME -like "*$Username*"}}
    $Info
} #Review - testing, Documentation