function Get-SHDComputerDiskLoad {
    <#
    .SYNOPSIS
        Gives the computerload of a target computer.
    .DESCRIPTION
        Gives the computerload of a target computer.
    .PARAMETER ComputerName
        A mandatory string that Target Computers
    .PARAMETER Credential
        Optional Credential
    .EXAMPLE
        Get-SHDComputerDiskLoad -ComputerName Desktop1

        Produces a disk load
    .EXAMPLE
        Get-SHDComputerDiskLoad -ComputerName Desktop1 -Credential

        Produces a disk load using the supplied credential.
    .INPUTS
        [String[]]
    .OUTPUTS
        [pscustomobject]
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
    $parameters = @{
        ComputerName = $ComputerName
        ScriptBlock  = {
            $Disk = Get-Counter -Counter "\PhysicalDisk(*)\Current Disk Queue Length" -SampleInterval 2 -MaxSamples 5
            $Load = ($Disk.CounterSamples.CookedValue | Measure-Object -Average).Average
            [PSCustomObject]@{
                Load    = $Load
            }
        }
    }
    if ($PSBoundParameters.ContainsKey('Credential')) { $parameters += @{Credential = $Credential } }
    Invoke-Command @parameters | Select-Object PSComputerName,Load
} #Review - Documentation