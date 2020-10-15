function Get-SHDComputerDesktopShortcuts {
    <#
    .SYNOPSIS
        Grabs target desktop(s) for shortcut information
    .DESCRIPTION
        Targerts mulitple computers, and either the public desktop or all the desktops for all the shortcuts. You can ask for just the names or you can ask for details which gives you the targetpath and arguments.
    .PARAMETER ComputerName
        A required list of computer names to grab the desktop information from.
    .PARAMETER Desktops
        A validated set of All or Public. All grabs all the desktops, while public only grabs the public desktop. This is defaulted to Public.
    .PARAMETER Arguments
        An option switch that will give more details like arguments, targetpath and more.
    .PARAMETER Credential
        Provided Credentials
    .EXAMPLE
        Get-SHDComputerDesktopShortcuts -ComputerName Desktop1

        Gives a list of all public desktop links on desktop 1
    .EXAMPLE
        Get-SHDComputerDesktopShortcuts -ComputerName Desktop1 -Desktops All

        Gives a list of all desktop links on desktop 1 from all profiles.
    .EXAMPLE
        Get-SHDComputerDesktopShortcuts -ComputerName Desktop1 -Arguments

        Gives a list of all public desktop on desktop 1 with the target path and arguments.
    .EXAMPLE
        Get-SHDComputerDesktopShortcuts -ComputerName Desktop2 -Arguments -Desktop All -Credential (Get-Credential)

        Gives a list of all profile's desktops on desktop2 and their arguments using the provided credentials.
    .INPUTS
        List of Computer Names
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
        [parameter(HelpMessage = "Level of Profiles, public default")][validateset("All","Public")]$Desktops = "Public",
        [parameter(HelpMessage = "Details or General")][Switch]$Arguments,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )

    $parameters = @{
        ComputerName = $ComputerName
        Scriptblock  = {
            param ($param1,$Param2)
            if (($param1 -notlike "Public") -and ($param1 -notlike "All")) { $param1 = "Public" }
            if ($param1 -like "Public") {
                $Shortcuts = Get-ChildItem "$($Env:HOMEDRIVE)\users\public\desktop" -Recurse -Include *.lnk -Force
            } else {
                $Shortcuts = Get-ChildItem "$($Env:HOMEDRIVE)\users\*\desktop" -Recurse -Include *.lnk -Force
            }
            if ($Param2 -eq $true) {
                $shell = New-Object -ComObject WScript.shell
                $Cuts = foreach ($Shortcut in $Shortcuts) {
                    [pscustomobject]@{
                        Username     = $Shortcut.fullname.split('\')[2]
                        ShortcutName = $Shortcut.Name
                        Target       = $Shell.CreateShortcut($Shortcut).targetpath
                        ShortcutArg  = $Shell.CreateShortcut($Shortcut).Arguments
                    }
                }
                [Runtime.InteropServices.Marshal]::ReleaseComObject($Shell) | Out-Null
                $Cuts
            } else {
                foreach ($Shortcut in $Shortcuts) {
                    [pscustomobject]@{
                        Fullname     = $Shortcut.fullname
                        Username     = $Shortcut.fullname.split('\')[2]
                    }
                }
            }
        }
        ArgumentList = $Desktops, $Arguments
    }
    if ($PSBoundParameters.ContainsKey('Credential')) { $parameters += @{Credential = $Credential } }
    if ($Arguments -eq $true) {
        if ($Desktops -like "All") {
            Invoke-Command @parameters | Sort-Object ShortcutName | Select-Object PSComputerName, Username, ShortcutName, Target, ShortcutArg
        } else {
            Invoke-Command @parameters | Select-Object PSComputerName,Username,ShortcutName,Target,ShortcutArg
        }
    } else {
        if ($Desktops -like "All") {
            Invoke-Command @parameters | Sort-Object $username | Select-Object PSComputerName, Username, FullName
        } else {
            Invoke-Command @parameters | Select-Object PSComputerName,FullName
        }
    }
} #Review - Testing, Documentation