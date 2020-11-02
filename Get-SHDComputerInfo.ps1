function Get-SHDComputerInfo {
    <#
    .SYNOPSIS
        Grabs general information from a target computer.
    .DESCRIPTION
        Grabs General Information from a target computer.
    .PARAMETER ComputerName
        Mandatory List of string of the target computer.
    .PARAMETER Credential
        Credential provided by end user for a different system.
    .EXAMPLE
        PS C:\Users\dbolding_adm> Get-SHDComputerInfo -Computername easw-adw

        ComputerName : Computer1
        Make         : LENOVO
        Model        : 10MR000000
        SerialNumber : MJ000000
        OS           : Microsoft Windows 10 Pro 64-bit
        RDP          : True
        SCreenLock   : False
        IPAddress    : 10.10.10.12
        SystemTime   : 11/2/2020 5:00:40 PM
        UpTime       : 16:44:39.6307200
    .INPUTS
        [string[]]
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
    foreach ($Computer in $ComputerName) {
        if (Test-Connection -ComputerName $Computer -Count 1 -Quiet) {
            if ($PSBoundParameters.ContainsKey('Credential')) {
                try {
                    $CIMSession = New-CimSession -ComputerName $Computer -Credential $Credential
                    $ComputerSystem = Get-CimInstance -ClassName win32_ComputerSystem -CimSession $CIMSession -Property Name, Manufacturer, Model, Status, PrimaryOwnername, SystemFamily, TotalPhysicalMemory
                    $ComputerProcess = Get-CimInstance -ClassName win32_process -CimSession $CIMSession
                    $ComputerOS = Get-CimInstance -ClassName Win32_OperatingSystem -CimSession $CIMSession
                    $ComputerBIOS = Get-CimInstance -ClassName win32_bios -CimSession $CIMSession
                    $RDP = if ($ComputerProcess | Where-Object { $_.name -like "mstsc.exe" }) { $true } else { $false }
                    $ScreenLock = if ($ComputerProcess | Where-Object { $_.name -like "LogonUI.exe" }) { $true } else { $false }
                    $TheIP = (Test-Connection -ComputerName $Computer -Count 1).DisplayAddress.ToString()
                    $Uptime = (New-TimeSpan -Start $Computeros.LastBootUpTime -End $computeros.LocalDateTime).tostring()
                    [pscustomobject]@{
                        ComputerName = $ComputerSystem.name
                        Make         = $ComputerSystem.Manufacturer
                        Model        = $ComputerSystem.Model
                        SerialNumber = $ComputerBIOS.SerialNumber
                        OS           = "$($ComputerOS.Caption) $($ComputerOS.OSArchitecture)"
                        RDP          = $RDP
                        SCreenLock   = $ScreenLock
                        IPAddress    = $TheIP
                        SystemTime   = $ComputerOS.LocalDateTime
                        UpTime       = $Uptime
                    }
                    Remove-CimSession -CimSession $CIMSession
                }
                catch {
                    try {
                        $ComputerSystem = Get-WmiObject -credential $Credential -Class win32_ComputerSystem
                        $ComputerProcess = Get-WmiObject -credential $Credential -Class win32_process
                        $ComputerOS = Get-WmiObject -credential $Credential -Class Win32_OperatingSystem
                        $ComputerBIOS = Get-WmiObject -credential $Credential -Class win32_bios
                        $RDP = if ($ComputerProcess | Where-Object { $_.name -like "mstsc.exe" }) { $true } else { $false }
                        $ScreenLock = if ($ComputerProcess | Where-Object { $_.name -like "LogonUI.exe" }) { $true } else { $false }
                        $TheIP = (Test-Connection -ComputerName $Computer -Count 1).DisplayAddress.ToString()
                        $Uptime = (New-TimeSpan -Start $Computeros.LastBootUpTime -End $computeros.LocalDateTime).tostring()
                        [pscustomobject]@{
                            ComputerName = $ComputerSystem.PSComputerName
                            Make         = $ComputerSystem.Manufacturer
                            Model        = $ComputerSystem.Model
                            SerialNumber = $ComputerBIOS.SerialNumber
                            OS           = "$($ComputerOS.Caption) $($ComputerOS.OSArchitecture)"
                            RDP          = $RDP
                            SCreenLock   = $ScreenLock
                            IPAddress    = $TheIP
                            SystemTime   = $ComputerOS.LocalDateTime
                            UpTime       = $Uptime
                        }
                    }
                    catch {
                        Write-Warning "Can Not Reach Data on $Computer"
                    }
                }
            }
            else {
                try {
                    $ComputerSystem = Get-CimInstance -ClassName win32_ComputerSystem -ComputerName $Computer -Property Name, Manufacturer, Model, Status, PrimaryOwnername, SystemFamily, TotalPhysicalMemory
                    $ComputerProcess = Get-CimInstance -ClassName win32_process -ComputerName $Computer
                    $ComputerOS = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $Computer
                    $ComputerBIOS = Get-CimInstance -ClassName win32_bios -ComputerName $Computer
                    $RDP = if ($ComputerProcess | Where-Object { $_.name -like "mstsc.exe" }) { $true } else { $false }
                    $ScreenLock = if ($ComputerProcess | Where-Object { $_.name -like "LogonUI.exe" }) { $true } else { $false }
                    $TheIP = (Test-Connection -ComputerName $Computer -Count 1).DisplayAddress.ToString()
                    $Uptime = (New-TimeSpan -Start $Computeros.LastBootUpTime -End $computeros.LocalDateTime).tostring()
                    [pscustomobject]@{
                        ComputerName = $ComputerSystem.PSComputerName
                        Make         = $ComputerSystem.Manufacturer
                        Model        = $ComputerSystem.Model
                        SerialNumber = $ComputerBIOS.SerialNumber
                        OS           = "$($ComputerOS.Caption) $($ComputerOS.OSArchitecture)"
                        RDP          = $RDP
                        SCreenLock   = $ScreenLock
                        IPAddress    = $TheIP
                        SystemTime   = $ComputerOS.LocalDateTime
                        UpTime       = $Uptime
                    }
                }
                catch {
                    try {
                        $ComputerSystem = Get-WmiObject -Class win32_ComputerSystem
                        $ComputerProcess = Get-WmiObject -Class win32_process
                        $ComputerOS = Get-WmiObject -Class Win32_OperatingSystem
                        $ComputerBIOS = Get-WmiObject -Class win32_bios
                        $RDP = if ($ComputerProcess | Where-Object { $_.name -like "mstsc.exe" }) { $true } else { $false }
                        $ScreenLock = if ($ComputerProcess | Where-Object { $_.name -like "LogonUI.exe" }) { $true } else { $false }
                        $TheIP = (Test-Connection -ComputerName $Computer -Count 1).DisplayAddress.ToString()
                        $Uptime = (New-TimeSpan -Start $Computeros.LastBootUpTime -End $computeros.LocalDateTime).tostring()
                        [pscustomobject]@{
                            ComputerName = $ComputerSystem.PSComputerName
                            Make         = $ComputerSystem.Manufacturer
                            Model        = $ComputerSystem.Model
                            SerialNumber = $ComputerBIOS.SerialNumber
                            OS           = "$($ComputerOS.Caption) $($ComputerOS.OSArchitecture)"
                            RDP          = $RDP
                            SCreenLock   = $ScreenLock
                            IPAddress    = $TheIP
                            SystemTime   = $ComputerOS.LocalDateTime
                            UpTime       = $Uptime
                        }
                    }
                    catch {
                        Write-Warning "Can Not Reach Data on $Computer"
                    }
                }
            }
        }
        else {
            Write-Warning "$Computer Offline."
        }
    }
} #Review - Testing, Documentation