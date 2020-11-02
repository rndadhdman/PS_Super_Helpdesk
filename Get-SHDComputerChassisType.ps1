function Get-SHDComputerChassisType {
    <#
    .SYNOPSIS
        Grabs the Chassis Type of target computer.
    .DESCRIPTION
        Grabs the chassis type of target computer.
    .PARAMETER ComputerName
        List of strings of the computer name.
    .EXAMPLE
        PS C:\Users\dbolding_adm> Get-SHDComputerChassisType -Computername easw-adw


        PSComputerName ChassisType
        -------------- -----------
        computer1      Desktop
    .INPUTS
        [string[]]
    .OUTPUTS
        pscustomobject
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
            $chassis = Get-CimInstance -Class win32_systemenclosure | Select-Object -ExpandProperty chassistypes
            $theChassis = switch ($chassis) {
                3 { "Desktop" }
                4 { "Low Profile Desktop" }
                5 { "Pizza Box" }
                6 { "Mini Tower" }
                7 { "Tower" }
                8 { "Portable" }
                9 { "Laptop" }
                10 { "Notebook" }
                11 { "Hand Held" }
                12 { "Docking Station" }
                13 { "All In One" }
                14 { "Sub Notebook" }
                15 { "Space-Saving" }
                16 { "Lunch Box" }
                17 { "Main System Chassis" }
                18 { "Expansion Chassis" }
                19 { "Sub Chassis" }
                20 { "Bus Expansion Chassis" }
                21 { "Peripheral Chassis" }
                22 { "Storage Chassis" }
                23 { "Rack Mount Chassis" }
                24 { "Sealed-case PC" }
                Default { "Unknown" }
            }
            [pscustomobject]@{
                Computername = $Computer
                ChassisType  = $theChassis
            }
        }
    }
    if ($PSBoundParameters.ContainsKey('Credential')) { $parameters += @{Credential = $Credential } }
    Invoke-Command @parameters | Select-Object PScomputername,ChassisType
} #review -order,testing,Documentation