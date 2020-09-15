<#
    Get-SHDComputerDesktopShortcuts - Errors
    Get-SHDComputerDiskLoad - No Load information
    Get-SHDComputerInfo - No Make model information 
    Get-SHDComputerLocalAccounts - Takes to much time 
    Get-SHDComputerLocalGroup - Requires a name 
    Get-SHDComputerLocalGroupMember and Get-SHDComputerLocalGroupMembers
    Get-SHDComputerLogicalNetworkDrive - No Info
    Get-SHDComputerLogicalRemovableDrives - No Info  
    Get-SHDComputerMemoryLoad - Error Message
    Get-SHDComputerPrinters - Error Messages 
    Get-SHDComputerRam - Error Message 
    Get-SHDComputerWindowsActivationStatus - Slow 
#>
#-------------------------Computer - Add -----------------------------------#
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

    .LINK
        https://www.bolding.us
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
    
    #Starting Computer Loop
    foreach ($computer in $Computername) {
        Write-Verbose "Testing Computer Conenctivity."
        #Testing if the computer is online if online, continue, if not, quit and let the end user know.
        if (Test-Connection -ComputerName $computer -Count 1 -Quiet) {
            
            #Starting the Group Loop if the computer can be connected. 
            foreach ($Group in $GroupName) {

                #starting the username loop
                Foreach ($User in $username) {

                    #We are going to try to set the group information now.
                    try {

                        #If the end user gave credentials this is where we are testing.
                        if ($PSBoundParameters.ContainsKey('Credential')) {

                            Write-Verbose "Invoking Command to add $user to $Group on $Computer with given permissions"
                            #we invoke the command to add the groups using the credentials given by the end user.
                            Invoke-Command -ComputerName $computer -Credential $Credential -ScriptBlock {

                                #Adds the user to the group from the arguments
                                Add-LocalGroupMember -Group $args[0] -Member $args[1] -Confirm:$false

                                #Returns something for those dang windows users. 
                                Get-LocalGroupMember -Group $args[0]

                                #We select what information we want from the get-localgroupmember command. 
                            } -ArgumentList $Group, $User | Select-Object PScomputername, ObjectClass, name, principalsource
                        }
                        else {
                            Write-Verbose "Invoking Command to add $user to $Group on $Computer with local powershell permissions."
                            #we invoke the command to add a group using the currently running powershell's credentials.
                            Invoke-Command -ComputerName $computer -ScriptBlock {

                                #Adds the user to the local group. 
                                Add-LocalGroupMember -Group $args[0] -Member $args[1] -Confirm:$false

                                #Dislpays this information for the windows users.
                                Get-LocalGroupMember -Group $args[0]
                            
                                #Selects the output information
                            } -ArgumentList $Group, $User | Select-Object PScomputername, ObjectClass, name, principalsource
                        }
                    }
                    catch {

                        #Lets the end user know there was a failure. 
                        Write-Warning "Unable to access $computer information."

                        #presents the failure. 
                        Write-Warning "$_"
                    }
                }
            }
        }
        else {

            #lets the end user know the target computer is offline. 
            Write-Warning "$Computer offline."
        }
    }
} #Review - Documentation

#-------------------------Computer - Add -----------------------------------#
#-------------------------Computer - Clear ---------------------------------#
function Clear-SHDComputerUserTemporaryFiles {
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
    foreach ($computer in $Computername) {
        if (Test-Connection -ComputerName $computer -Count 1 -Quiet) {
            foreach ($User in $Username) {
                if ($PSBoundParameters.ContainsKey('Credential')) {
                    if (Test-Path -Path "\\$Computer\c$\Users\$Username") {
                        Remove-Item "\\$Computer\c$\Users\$Username\AppData\Local\Temp\*" -Recurse -Force -Verbose -ErrorAction SilentlyContinue -Credential $Credential -Confirm:$false
                    }
                }
                else {
                    Remove-Item "\\$Computer\c$\Users\$Username\AppData\Local\Temp\*" -Recurse -Force -Verbose -ErrorAction SilentlyContinue -Confirm:$false
                }
            }
        }
    }
} #Review - Testing, Documentation

#-------------------------Computer - Clear ---------------------------------#
#-------------------------Computer - Disable -------------------------------#
function Disable-SHDComputerRDP {
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
                    Invoke-Command -ComputerName $computer -Credential $Credential -ScriptBlock {
                        Disable-NetFirewallRule -DisplayName "Remote Desktop"
                        Set-ItemProperty ‘HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\‘ -Name “fDenyTSConnections” -Value 1
                        Set-ItemProperty ‘HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\‘ -Name “UserAuthentication” -Value 0
                        Get-LocalGroupMember -Group "Remote Desktop Users" | ForEach-Object { Remove-LocalGroupMember -Group "Remote Desktop Users" -Member $_.Name -Confirm:$false }
                    }
                }
                else {
                    Invoke-Command -ComputerName $computer -ScriptBlock {
                        Disable-NetFirewallRule -DisplayName "Remote Desktop"
                        Set-ItemProperty ‘HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\‘ -Name “fDenyTSConnections” -Value 1
                        Set-ItemProperty ‘HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\‘ -Name “UserAuthentication” -Value 0
                        Get-LocalGroupMember -Group "Remote Desktop Users" | ForEach-Object { Remove-LocalGroupMember -Group "Remote Desktop Users" -Member $_.Name -Confirm:$false }
                    }
                }
            }
            catch {
                Write-Warning "Unable to capture Data from $Computer."
            }
        }
        else {
            Write-Warning "$Computer is offline."
        }
    } 
} #Review - Testing, Documentation

#-------------------------Computer - Disable -------------------------------#
#-------------------------Computer - Enable --------------------------------#
function Enable-SHDComputerRDP {
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
                    Invoke-Command -ComputerName $computer -Credential $Credential -ScriptBlock {
                        Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' 
                        Set-ItemProperty ‘HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\‘ -Name “fDenyTSConnections” -Value 0
                        Set-ItemProperty ‘HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\‘ -Name “UserAuthentication” -Value 1
                    }
                }
                else {
                    Invoke-Command -ComputerName $computer -ScriptBlock {
                        Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' 
                        Set-ItemProperty ‘HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\‘ -Name “fDenyTSConnections” -Value 0
                        Set-ItemProperty ‘HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\‘ -Name “UserAuthentication” -Value 1
                    }
                }
            }
            catch {
                Write-Warning "Unable to capture Data from $Computer."
            }
        }
        else {
            Write-Warning "$Computer is offline."
        }
    } 
} #Review - Testng, Documentation
function enable-SHDComputerBitlocker {
    [cmdletbinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Provide the target hostname",
            Mandatory = $true)][Alias('Hostname', 'cn')][String[]]$Computername,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )
    foreach ($Computer in $Computername) {
        if (Test-Connection -computername $Computer -Count 1 -Quiet) {
            if ($PSBoundParameters.ContainsKey('Credential')) {
                invoke-command -ComputerName $Computer -Credential $Credential -ScriptBlock {
                    import-module bitlocker
                    $BitVolume = Get-BitLockerVolume -MountPoint "$($env:SystemDrive)"
                    if ($BitVolume.ProtectionStatus -like "off") {
                        $TPMChip = Get-CimInstance -ClassName win32_tpm -Namespace "root\cimv2\Security\MicrosoftTPM"
                        if ($TPMChip.IsEnabled_InitialValue -eq $true) {
                            if ($TPMChip.IsActivated_InitialValue -eq $true) {
                                Enable-BitLocker -MountPoint "$($env:SystemDrive)" -EncryptionMethod Aes128 -TpmProtector -SkipHardwareTest 
                                Start-Sleep -Seconds 15 -Verbose
                                Get-BitLockerVolume -MountPoint "$($env:SystemDrive)"
                            }
                            else {
                                write-warning "$Computer TPM chip is not actiavted."
                            }
                        }
                        else {
                            Write-Warning "$Computer TPM chip is not enabled. "
                        }
                    }
                    else {
                        $BitVolume
                    }
                }
            }
            else {
                invoke-command -computername $Computer -ScriptBlock {
                    import-module bitlocker
                    $BitVolume = Get-BitLockerVolume -MountPoint "$($env:SystemDrive)"
                    if ($BitVolume.ProtectionStatus -like "off") {
                        $TPMChip = Get-CimInstance -ClassName win32_tpm -Namespace "root\cimv2\Security\MicrosoftTPM"
                        if ($TPMChip.IsEnabled_InitialValue -eq $true) {
                            if ($TPMChip.IsActivated_InitialValue -eq $true) {
                                Enable-BitLocker -MountPoint "$($env:SystemDrive)" -EncryptionMethod Aes128 -TpmProtector -SkipHardwareTest 
                                Start-Sleep -Seconds 15 -Verbose
                                Get-BitLockerVolume -MountPoint "$($env:SystemDrive)"
                            }
                            else {
                                write-warning "$Computer TPM chip is not actiavted."
                            }
                        }
                        else {
                            Write-Warning "$Computer TPM chip is not enabled. "
                        }
                    }
                    else {
                        $BitVolume
                    }
                }
            }
        }
        else {
            Write-Warning "$Computer is offline."
        }
    }
} #Review - Testing, Documentation
#-------------------------Computer - Enable --------------------------------#
#-------------------------Computer - Get -----------------------------------#
function Get-SHDComputerActiveNetworking {
    [cmdletbinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Provide the target hostname",
            Mandatory = $true)][Alias('Hostname', 'cn')][String[]]$Computername,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )
    foreach ($Computer in $Computername) {
        if (Test-Connection -ComputerName $Computer -Count 1 -Quiet) {
            if ($PSBoundParameters.ContainsKey('Credential')) {
                try {
                    $CIMSession = New-CimSession -ComputerName $Computer -Credential $Credential
                    $networkConfig = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -CimSession $CIMSession | Where-Object { $_.IPEnabled -eq $true }
                    $ComputerNetwork = Get-CimInstance -Class win32_networkadapter -CimSession $CIMSession
                    foreach ($Net in $networkConfig) {
                        $CNet = $ComputerNetwork | Where-Object { $_.MACAddress -like $net.MACAddress }
                        [pscustomobject]@{
                            ComputerName     = $CNet.PScomputername
                            ConnectionName   = $CNet.ProductName
                            ConnectionID     = $Cnet.NetConnectionID
                            MacAddress       = $Cnet.MACAddress
                            Subnet           = $net.IPSubnet
                            DefaultGateway   = $net.DefaultIPGateway[0]
                            DNSDomain        = $net.DNSDomain
                            PrimaryDNS       = $net.DNSServerSearchOrder[0]
                            SecondaryDNS     = $net.DNSServerSearchOrder[0]
                            DHCPEnabled      = $net.DHCPEnabled
                            DHCPServer       = $net.DHCPServer
                            DHCPLeaseExpires = $net.DHCPLeaseExpires
                        }
                    }
                    Remove-CimSession -CimSession $CIMSession
                }
                catch {
                    try {
                        $networkConfig = Get-WimObject -ClassName Win32_NetworkAdapterConfiguration -ComputerName $Computer -Credential $Credential | Where-Object { $_.IPEnabled -eq $true }
                        $ComputerNetwork = Get-WimObject -Class win32_networkadapter -ComputerName $Computer -Credential $Credential 
                        foreach ($Net in $networkConfig) {
                            $CNet = $ComputerNetwork | Where-Object { $_.MACAddress -like $net.MACAddress }
                            [pscustomobject]@{
                                ComputerName     = $CNet.PScomputername
                                ConnectionName   = $CNet.ProductName
                                ConnectionID     = $Cnet.NetConnectionID
                                MacAddress       = $Cnet.MACAddress
                                Subnet           = $net.IPSubnet
                                DefaultGateway   = $net.DefaultIPGateway[0]
                                DNSDomain        = $net.DNSDomain
                                PrimaryDNS       = $net.DNSServerSearchOrder[0]
                                SecondaryDNS     = $net.DNSServerSearchOrder[0]
                                DHCPEnabled      = $net.DHCPEnabled
                                DHCPServer       = $net.DHCPServer
                                DHCPLeaseExpires = $net.DHCPLeaseExpires
                            }
                        }
                    }
                    catch {
                        write-warning "Unable to access $Computer Data."
                    }
                }
            }
            else {
                try {
                    $networkConfig = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -ComputerName $Computer | Where-Object { $_.IPEnabled -eq $true }
                    $ComputerNetwork = Get-CimInstance -Class win32_networkadapter -ComputerName $Computer
                    foreach ($Net in $networkConfig) {
                        $CNet = $ComputerNetwork | Where-Object { $_.MACAddress -like $net.MACAddress }
                        [pscustomobject]@{
                            ComputerName     = $CNet.PScomputername
                            ConnectionName   = $CNet.ProductName
                            ConnectionID     = $Cnet.NetConnectionID
                            MacAddress       = $Cnet.MACAddress
                            Subnet           = $net.IPSubnet
                            DefaultGateway   = $net.DefaultIPGateway[0]
                            DNSDomain        = $net.DNSDomain
                            PrimaryDNS       = $net.DNSServerSearchOrder[0]
                            SecondaryDNS     = $net.DNSServerSearchOrder[0]
                            DHCPEnabled      = $net.DHCPEnabled
                            DHCPServer       = $net.DHCPServer
                            DHCPLeaseExpires = $net.DHCPLeaseExpires
                        }
                    }
                }
                catch {
                    try {
                        $networkConfig = Get-WimObject -ClassName Win32_NetworkAdapterConfiguration -ComputerName $Computer | Where-Object { $_.IPEnabled -eq $true }
                        $ComputerNetwork = Get-WimObject -Class win32_networkadapter -ComputerName $Computer 
                        foreach ($Net in $networkConfig) {
                            $CNet = $ComputerNetwork | Where-Object { $_.MACAddress -like $net.MACAddress }
                            [pscustomobject]@{
                                ComputerName     = $CNet.PScomputername
                                ConnectionName   = $CNet.ProductName
                                ConnectionID     = $Cnet.NetConnectionID
                                MacAddress       = $Cnet.MACAddress
                                Subnet           = $net.IPSubnet
                                DefaultGateway   = $net.DefaultIPGateway[0]
                                DNSDomain        = $net.DNSDomain
                                PrimaryDNS       = $net.DNSServerSearchOrder[0]
                                SecondaryDNS     = $net.DNSServerSearchOrder[0]
                                DHCPEnabled      = $net.DHCPEnabled
                                DHCPServer       = $net.DHCPServer
                                DHCPLeaseExpires = $net.DHCPLeaseExpires
                            }
                        }
                    }
                    catch {
                        write-warning "Unable to access $Computer Data."
                    }
                }
            }
        }
        else {
            Write-Warning "$Computer is Offline"
        }
    }
} #Review - Testing, Documentation
function Get-SHDComputerBattery {
    [cmdletbinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Provide the target hostname",
            Mandatory = $true)][Alias('Hostname', 'cn')][String[]]$Computername,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )
    #    if ($PSBoundParameters.ContainsKey('Credential')) {$Credential = $Credential | ConvertTo-SecureString}
    foreach ($Computer in $Computername) {
        if (Test-Connection -ComputerName $Computer -Quiet -Count 1) {
            Try {
                if ($PSBoundParameters.ContainsKey('Credential')) {
                    $cimsession = New-CimSession -ComputerName $Computer -Credential $Credential -Authentication Kerberos
                    Get-CimInstance -Class win32_battery -CimSession $cimsession | Select-Object pscomputername, Name, Caption, status, EstimatedRunTime, EstimatedChargeRemaining, DesignVoltage
                    Remove-CimSession $cimsession
                }
                else {
                    Get-CimInstance -Class win32_battery -ComputerName $Computer | Select-Object pscomputername, Name, Caption, status, EstimatedRunTime, EstimatedChargeRemaining, DesignVoltage
                }
            }
            catch {
                Try {
                    if ($PSBoundParameters.ContainsKey('Credential')) {
                        Get-WmiObject -Class win32_battery -ComputerName $Computer -Credential $Credential | Select-Object pscomputername, Name, Caption, status, EstimatedRunTime, EstimatedChargeRemaining, DesignVoltage
                    }
                    else {
                        Get-WmiObject -Class win32_battery -ComputerName $Computer | Select-Object pscomputername, Name, Caption, status, EstimatedRunTime, EstimatedChargeRemaining, DesignVoltage
                    }
                }
                catch {
                    Write-Warning "Unable to capture Data from $Computer"
                }
            }
        }
        else {
            Write-Warning "$Computer Offline"
        }
    }
} #Review - Documentation
function Get-SHDComputerBios {
    [cmdletbinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Provide the target hostname",
            Mandatory = $true)][Alias('Hostname', 'cn')][String[]]$Computername,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )
    foreach ($Computer in $Computername) {
        if (Test-Connection -ComputerName $Computer -Quiet -Count 1) {
            Try {
                if ($PSBoundParameters.ContainsKey('Credential')) {
                    Get-WmiObject -Class win32_bios -ComputerName $Computer -Credential $Credential | Select-Object pscomputername, name, manufacturer, SMBIOSBIOSVersion, Version, serialnumber
                }
                else {
                    Get-WmiObject -Class win32_bios -ComputerName $Computer | Select-Object pscomputername, name, manufacturer, SMBIOSBIOSVersion, Version, serialnumber 
                }
            }
            catch {
                Try {
                    if ($PSBoundParameters.ContainsKey('Credential')) {
                        $cimsession = New-CimSession -ComputerName $Computer -Credential $Credential
                        Get-CimInstance -Class win32_bios -CimSession $cimsession | Select-Object pscomputername, name, manufacturer, SMBIOSBIOSVersion, Version, serialnumber 
                        Remove-CimSession $cimsession
                    }
                    else {
                        Get-CimInstance -Class win32_bios -ComputerName $Computer | Select-Object pscomputername, name, manufacturer, SMBIOSBIOSVersion, Version, serialnumber 
                    }
                }
                catch {
                    Write-Warning "Unable to capture Data from $Computer"
                }
            }
        }
        else {
            Write-Warning "$Computer Offline"
        }
    }
} #review - Order,testing,Documentation
function Get-SHDComputerBitlockerStatus {
    <#
    .SYNOPSIS
    .DESCRIPTION
    .PARAMETER
    .EXAMPLE
    .INPUTS
    .OUTPUTS
    .NOTES
    .LINK
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
                    invoke-command -ComputerName $Computer -Credential $Credential -ScriptBlock {
                        Get-BitLockerVolume 
                    } | Select-Object PSComputerName, ProtectionStatus, MountPoint, EncryptionMethod, EncryptionPercentage, VolumeStatus, KeyProtector
                }
                else {
                    invoke-command -ComputerName $Computer -ScriptBlock {
                        Get-BitLockerVolume 
                    } | Select-Object PSComputerName, ProtectionStatus, MountPoint, EncryptionMethod, EncryptionPercentage, VolumeStatus, KeyProtector
                }
            }
            catch {
                Write-Warning "Unable to capture Data from $Computer."
            }
        }
        else {
            Write-Warning "$Computer is offline."
        }
    }
} # Review - Order,testing,Documentation

function Get-SHDComputerChassisType {
    [cmdletbinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Provide the target hostname",
            Mandatory = $true)][Alias('Hostname', 'cn')][String[]]$Computername,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )
    foreach ($Computer in $Computername) {
        if (Test-Connection -ComputerName $Computer -Quiet -Count 1) {
            Try {
                if ($PSBoundParameters.ContainsKey('Credential')) {
                    $cimsession = New-CimSession -ComputerName $Computer -Credential $Credential
                    $chassis = Get-CimInstance -Class win32_systemenclosure -CimSession $cimsession | Select-Object -ExpandProperty chassistypes  
                    Remove-CimSession $cimsession
                }
                else {
                    $chassis = Get-CimInstance -Class win32_systemenclosure -computer $Computer | Select-Object -ExpandProperty chassistypes  
                }
            }
            catch {
                Write-Warning "Unable to capture Data from $Computer"
            }
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
        else {
            Write-Warning "$Computer Offline"
        }
    }
} #review -order,testing,Documentation - Does not dislpay information
function Get-SHDComputerCPU {
    [cmdletbinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Provide the target hostname",
            Mandatory = $true)][Alias('Hostname', 'cn')][String[]]$Computername,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )
    foreach ($Computer in $Computername) {
        if (Test-Connection -ComputerName $Computer -Quiet -Count 1) {
            Try {
                if ($PSBoundParameters.ContainsKey('Credentials')) {
                    $ComputerProcessor = Get-WmiObject -Class win32_processor -ComputerName $Computer -Credential $Credential
                    $ProcessorChip = @()
                    Foreach ($Processor in $ComputerProcessor) {
                        $CPULoad = $Processor | measure-object -Property loadpercentage -average | Select-Object -ExpandProperty average
                        $ProcessorChip += [pscustomobject][Ordered]@{
                            Computername  = $Processor.pscomputername
                            ProcessorName = $Processor.name
                            DeviceID      = $Processor.DeviceID
                            Bit           = $Processor.datawidth
                            MaxSpeed      = $Processor.maxclockspeed
                            SocketSet     = $Processor.socketdesignation
                            L3Size        = $Processor.l3cachesize
                            CoreCount     = $Processor.numberofcores
                            ThreadedCores = $Processor.numberoflogicalprocessors
                            ThreadCount   = $Processor.ThreadCount
                            ProcessorID   = $Processor.ProcessorID
                            CurrentLoad   = $CPULoad
                        }
                    }
                    $ProcessorChip
                }
                else {
                    $ComputerProcessor = Get-WmiObject -Class win32_processor -ComputerName $Computer
                    $ProcessorChip = @()
                    Foreach ($Processor in $ComputerProcessor) {
                        $CPULoad = $Processor | measure-object -Property loadpercentage -average | Select-Object -ExpandProperty average
                        $ProcessorChip += [pscustomobject][Ordered]@{
                            Computername  = $Processor.pscomputername
                            ProcessorName = $Processor.name
                            DeviceID      = $Processor.DeviceID
                            Bit           = $Processor.datawidth
                            MaxSpeed      = $Processor.maxclockspeed
                            SocketSet     = $Processor.socketdesignation
                            L3Size        = $Processor.l3cachesize
                            CoreCount     = $Processor.numberofcores
                            ThreadedCores = $Processor.numberoflogicalprocessors
                            ThreadCount   = $Processor.ThreadCount
                            ProcessorID   = $Processor.ProcessorID
                            CurrentLoad   = $CPULoad
                        }
                    }
                    $ProcessorChip
                }
            }
            catch {
                Try {
                    if ($PSBoundParameters.ContainsKey('Credentials')) {
                        $cimsession = New-CimSession -ComputerName $Computer -Credential $Credential
                        $ComputerProcessor = Get-CimInstance -Class win32_processor -CimSession $cimsession
                        Remove-CimSession $cimsession
                        $ProcessorChip = @()
                        Foreach ($Processor in $ComputerProcessor) {
                            $CPULoad = $Processor | measure-object -Property loadpercentage -average | Select-Object -ExpandProperty average
                            $ProcessorChip += [pscustomobject][Ordered]@{
                                Computername  = $Processor.pscomputername
                                ProcessorName = $Processor.name
                                DeviceID      = $Processor.DeviceID
                                Bit           = $Processor.datawidth
                                MaxSpeed      = $Processor.maxclockspeed
                                SocketSet     = $Processor.socketdesignation
                                L3Size        = $Processor.l3cachesize
                                CoreCount     = $Processor.numberofcores
                                ThreadedCores = $Processor.numberoflogicalprocessors
                                ThreadCount   = $Processor.ThreadCount
                                ProcessorID   = $Processor.ProcessorID
                                CurrentLoad   = $CPULoad
                            }
                        }
                        $ProcessorChip
                    }
                    else {
                        $ComputerProcessor = Get-CimInstance -Class win32_processor -ComputerName $Computer
                        $ProcessorChip = @()
                        Foreach ($Processor in $ComputerProcessor) {
                            $CPULoad = $Processor | measure-object -Property loadpercentage -average | Select-Object -ExpandProperty average
                            $ProcessorChip += [pscustomobject][Ordered]@{
                                Computername  = $Processor.pscomputername
                                ProcessorName = $Processor.name
                                DeviceID      = $Processor.DeviceID
                                Bit           = $Processor.datawidth
                                MaxSpeed      = $Processor.maxclockspeed
                                SocketSet     = $Processor.socketdesignation
                                L3Size        = $Processor.l3cachesize
                                CoreCount     = $Processor.numberofcores
                                ThreadedCores = $Processor.numberoflogicalprocessors
                                ThreadCount   = $Processor.ThreadCount
                                ProcessorID   = $Processor.ProcessorID
                                CurrentLoad   = $CPULoad
                            }
                        }
                        $ProcessorChip
                    }
                }
                catch {
                    Write-Warning "Unable to capture Data from $Computer"
                }
            }
        }
        else {
            Write-Warning "$Computer Offline"
        }
    }
} #Review - Order,testing,Documentation - Does not Display Information
function Get-SHDComputerCurrentUser {
    [cmdletbinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Provide the target hostname",
            Mandatory = $true)][Alias('Hostname', 'cn')][String[]]$Computername,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )
    $Return = @()
    foreach ($Computer in $Computername) {
        if (Test-Connection -ComputerName $Computer -Quiet -Count 1) {
            if ($PSBoundParameters.ContainsKey('Credential')) {
                try {
                    Invoke-Command -ComputerName $Computer -Credential $Credential -ScriptBlock {
                        $Test = (((quser /server:"$($args[0])" 2> $null) -replace '^>', '') -replace '\s{2,}', ',') | ForEach-Object {
                            if ($_.Split(',').Count -eq 5) {
                                Write-Output ($_ -replace '(^[^,]+)', '$1,')
                            }
                            else {
                                Write-Output $_
                            }
                        } | ConvertFrom-Csv 
                        $Test | Where-Object { $_."IDLE TIME" -like "." } | ForEach-Object { $_."IDLE TIME" = $null } 
                        $Test
                    } -ArgumentList $Computer | sort-object PSComputerName | Select-Object Username, SessionName, ID, State, "Idle Time", "Logon Time"
                }
                catch {
                    Write-Warning "$Computer Presented an error."
                }
                
            }
            else {
                try {
                    Invoke-Command -ComputerName $Computer -ScriptBlock {
                        $Test = (((quser /server:"$($args[0])" 2> $null) -replace '^>', '') -replace '\s{2,}', ',') | ForEach-Object {
                            if ($_.Split(',').Count -eq 5) {
                                Write-Output ($_ -replace '(^[^,]+)', '$1,')
                            }
                            else {
                                Write-Output $_
                            }
                        } | ConvertFrom-Csv 
                        $Test | Where-Object { $_."IDLE TIME" -like "." } | ForEach-Object { $_."IDLE TIME" = $null } 
                        $Test
                    } -ArgumentList $Computer | sort-object PSComputerName | Select-Object Username, SessionName, ID, State, "Idle Time", "Logon Time"
                }
                catch {
                    Write-Warning "$Computer Presented an error."
                }
            }
        }
        else {
            Write-Warning "$Computer Offline"
        }
    }
    $Return
} #Review - testing, Documentation
function Get-SHDComputerDesktopShortcuts {
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
        if (Test-Connection -computername $Computer -Quiet -Count 1) {
            try {
                if ($PSBoundParameters.ContainsKey('Credential')) {
                    invoke-command -ComputerName $Computer -Credential $Credential -ScriptBlock {
                        $Shortcuts = Get-ChildItem "$($Env:HOMEDRIVE)\users\public\desktop" -Recurse -Include *.lnk -Force
                        $shell = New-Object -ComObject WScript.shell
                        foreach ($Shortcut in $Shortcuts) {
                            [pscustomobject]@{
                                Computername = $args[0]
                                ShortcutName = $Shortcut.Name
                                Target       = $Shell.CreateShortcut($Shortcut).targetpath
                                ShortcutArgs = $shell.CreateShortcut($Shortcuts).Arguments
                            }
                        }
                    } -ArgumentList $Computer
                }
                else {
                    invoke-command -ComputerName $Computer -ScriptBlock {
                        $Shortcuts = Get-ChildItem "$($Env:HOMEDRIVE)\users\public\desktop" -Recurse -Include *.lnk -Force
                        $shell = New-Object -ComObject WScript.shell
                        foreach ($Shortcut in $Shortcuts) {
                            [pscustomobject]@{
                                Computername = $args[0]
                                ShortcutName = $Shortcut.Name
                                Target       = $Shell.CreateShortcut($Shortcut).targetpath
                                ShortcutArgs = $shell.CreateShortcut($Shortcuts).Arguments
                            }
                        }
                    } -ArgumentList $Computer
                }
            }
            catch {
                write-warning "$Computer data can not be reached."
            }
        }
        else {
            Write-Warning "$Computer offline."
        }
    }
} #Review - Testing, Documentation
function Get-SHDComputerDesktopShortcutArguments {
    [cmdletbinding()]
    param (
        [parameter(HelpMessage = "Computer Target", Mandatory = $true)][string[]]$ComputerName
    )
    foreach ($Computer in $ComputerName) {
        if (Test-Connection -ComputerName $Computer -Quiet -Count 1) {
            $Shortcuts = Get-ChildItem -Recurse "\\$Computer\C$\users\public\Desktop\" -Include *.lnk -Force
            $Shell = New-Object -ComObject WScript.Shell    
            foreach ($Shortcut in $Shortcuts) {
                [pscustomobject]@{
                    ComputerName = $Computer 
                    ShortcutName = $Shortcut.Name;
                    Target       = $Shell.CreateShortcut($Shortcut).targetpath
                    ShortcutArg  = $Shell.CreateShortcut($Shortcut).Arguments
                }
            }

            [Runtime.InteropServices.Marshal]::ReleaseComObject($Shell) | Out-Null
        }
    }
} #Review - Testing, Documentation
function Get-SHDComputerDiskLoad {
    [cmdletbinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Provide the target hostname",
            Mandatory = $true)][Alias('Hostname', 'cn')][String[]]$Computername,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )
    foreach ($Computer in $Computername) {
        if (Test-Connection -ComputerName $Computer -Count 1 -Quiet) {
            if ($PSBoundParameters.ContainsKey('Credential')) {
                $Disk = invoke-command -ComputerName $Computer -Credential $Credential -ScriptBlock {
                    Get-Counter -Counter "\PhysicalDisk(*)\Current Disk Queue Length" -SampleInterval 2 -MaxSamples 5
                }
            }
            else {
                $Disk = invoke-command -ComputerName $Computer -ScriptBlock {
                    Get-Counter -Counter "\PhysicalDisk(*)\Current Disk Queue Length" -SampleInterval 2 -MaxSamples 5
                }
            }
        }
        else {
            Write-Warning "$Computer Offline"
        }
        if ($null -ne $Disk) {
            $Load = ($Disk.CounterSamples.CookedValue | Measure-Object -Average).Average
            [PSCustomObject]@{
                ComputerName = $Computer
                Load         = $Load
            }
        }
        else {
            Write-Warning "Data was not collected for $Computer"
        }
    }
} #Review - Documentation
Function Get-SHDComputerDotNetFrameWork {
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
                    Invoke-Command -ComputerName $computer -Credential $Credential -ScriptBlock {
                        Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -recurse |
                        Get-ItemProperty -name Version -EA 0 |
                        Where-Object -FilterScript { $_.PSChildName -match '^(?!S)\p{L}' } |
                        Select-Object -Property PSChildName, Version
                    } | Sort-Object Version | Select-Object PSComputerName, PSChildName, Version
                }
                else {
                    Invoke-Command -ComputerName $computer -ScriptBlock {
                        Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -recurse |
                        Get-ItemProperty -name Version -EA 0 |
                        Where-Object -FilterScript { $_.PSChildName -match '^(?!S)\p{L}' } |
                        Select-Object -Property PSChildName, Version
                    } | Sort-Object Version | Select-Object PSComputerName, PSChildName, Version
                }
            }
            catch {
                Write-Warning "Unable to capture Data from $Computer."
            }
        }
        else {
            Write-Warning "$Computer is offline."
        }
    }
} #Review - Testing, Documentation
Function Get-SHDComputerDotNetFrameWorkTypeAccelerator {
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
                    Invoke-Command -ComputerName $computer -Credential $Credential -ScriptBlock {
                        [System.Management.Automation.PSObject].Assembly.GetType("System.Management.Automation.TypeAccelerators")::get
                    } 
                }
                else {
                    Invoke-Command -ComputerName $computer -ScriptBlock {
                        [System.Management.Automation.PSObject].Assembly.GetType("System.Management.Automation.TypeAccelerators")::get
                    }
                }
            }
            catch {
                Write-Warning "Unable to capture Data from $Computer."
            }
        }
        else {
            Write-Warning "$Computer is offline."
        }
    }
} #Review - Testing, Documentation
function Get-SHDComputerEnvironment {
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
                    Get-CimInstance -ClassName Win32_Environment -CimSession $CIMSession
                    Remove-CimSession $CIMSession
                }
                else {
                    Get-CimInstance -ClassName Win32_Environment -ComputerName $Computer
                }
            }
            catch {
                try {
                    if ($PSBoundParameters.ContainsKey('Credential')) {
                        Get-WmiObject -ClassName Win32_Environment -computername $Computer -Credential $Credential
                    }
                    else {
                        Get-WmiObject -ClassName Win32_Environment -computername $computer
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
} #Review - Testing, Documentaton
function Get-SHDComputerGPO {
    <#
		.SYNOPSIS
		    Grabs the Group Policy Information from a collection of computers or a single user from a collection of computers.
		.DESCRIPTION
            Get-SHDComputerGPO grabs group policy informatin from a collection of computers. Or you can target a single user on those collection of computers and grab it's group policy information.    
        .PARAMETER ComputerName
            [string[]] The Computer Names of each target computer. 
        .PARAMETER Username
            [string] The username of a target user on this computer. 
		.PARAMETER Credential
		    if you choose to use a credential, this is where you would add this information.
            if you choose not to use credential, then the script will use the currently running Credential. 
		.EXAMPLE
		    Get-ComputerPCGPO -ComputerName [string[]]

            This will use the currently running login to access server 1 and server 2. Then it 
            will produce the GPO information.
		.EXAMPLE
            Get-SHDComputerGPO -ComputerName [string[]] -Credential (get-credential)		    

            This will prompt you to put in the credential information needed to access the off domain
            computer and apply the gpo settings to it. 
        .EXAMPLE
		    Get-SHDComputerGPO -ComputerName [string[]] -username [string]

            This will use the currently running login to access each computer in the collection and grab a single username group policy information.
		.EXAMPLE
            Get-SHDComputerGPO -ComputerName [string[]] -Credential (get-credential) -username [string]

            This will use the supplied credentials to access each computer in the collection and grab a single username group policy information.
		.LINK
		    https://github.com/boldingdp/
		.NOTES
            Author: David Bolding
            Site: https://github.com/boldingdp/
	#>    
    [cmdletbinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Provide the target hostname",
            Mandatory = $true)]
        [Alias('Hostname', 'cn')]
        [String[]]$Computername,
        [Parameter(HelpMessage = "Target a single user in the list of users")]
        [Alias('Samaccountname')]
        [string]$Username,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )

    #we start the loop of computers
    foreach ($Computer in $Computername) {

        #Check for the username flag. If it's present, then we start the username process. 
        if ($PSBoundParameters.ContainsKey('Username')) {
            $SID = $Null 
            try {
                if ($PSBoundParameters.ContainsKey('Credential')) {
                    $SID = (Get-ADUser -Identity $username -Credential $Credential).sid.value -replace "-", "_"
                }
                else {
                    $SID = (Get-ADUser -Identity $username).sid.value -replace "-", "_"
                }
            }
            Catch {
                Write-Warning "$username does not exist in active directory."
                break
            }
        }
        #We test if the computer is on.
        if (Test-Connection -ComputerName $Computer -Quiet -Count 1) {
            Try {
                if ($PSBoundParameters.ContainsKey('Username')) {
                    if ($PSBoundParameters.ContainsKey('Credential')) {
                        #We try older wmiobjects as many of our system still understands wmiobjects with the Credential. We are grabbing the GPO information
                        $UserPolicies = Get-WmiObject -Namespace root\rsop\User\$SID -Query "select * from RSOP_GPO" -ComputerName $Computer -Credential $Credential 2>$Null
                        $UserTimes = Get-WmiObject -Namespace root\rsop\User\$SID -Query "select * from RSOP_ExtensionStatus" -ComputerName $Computer -Credential $Credential 2>$Null
                        $UserGPLink = Get-WmiObject -Namespace root\rsop\User\$SID -Query "select * from RSOP_GPLink" -ComputerName $Computer -Credential $Credential 2>$Null
                    }
                    else {
                        $UserPolicies = Get-WmiObject -Namespace root\rsop\User\$SID -Query "select * from RSOP_GPO" -ComputerName $Computer 2>$Null
                        $UserTimes = Get-WmiObject -Namespace root\rsop\User\$SID -Query "select * from RSOP_ExtensionStatus" -ComputerName $Computer 2>$Null
                        $UserGPLink = Get-WmiObject -Namespace root\rsop\User\$SID -Query "select * from RSOP_GPLink" -ComputerName $Computer 2>$Null
                    }
                }
                else {
                    if ($PSBoundParameters.ContainsKey('Credential')) {
                        $returns = Get-WmiObject -Namespace root\rsop\Computer -Query "select * from RSOP_GPO" -ComputerName $Computer -Credential $Credential
                        $returnLinks = Get-WmiObject -Namespace root\rsop\Computer -Query "select * from RSOP_GPLink" -ComputerName $Computer -Credential $Credential
                    }
                    else {
                        $returns = Get-WmiObject -Namespace root\rsop\Computer -Query "select * from RSOP_GPO" -ComputerName $Computer
                        $returnLinks = Get-WmiObject -Namespace root\rsop\Computer -Query "select * from RSOP_GPLink" -ComputerName $Computer
                    }
                }                
            }
            Catch {
                Try {

                    #Powershell 7 and above does not understand get-wmiobject anymore. Thus we need to use Cim objects. 
                    if ($PSBoundParameters.ContainsKey('Username')) {
                        if ($null -ne $SID) {
                            if ($PSBoundParameters.ContainsKey('Credential')) {
                                $CIMSession = New-CimSession -ComputerName $Computer -Credential $Credential
                                $UserPolicies = Get-CimInstance -Namespace root\rsop\User\$SID -Query "select * from RSOP_GPO" -CimSession $CimSession 2>$Null
                                $UserTimes = Get-CimInstance -Namespace root\rsop\User\$SID -Query "select * from RSOP_ExtensionStatus" -CimSession $CIMSession 2>$Null
                                $UserGPLink = Get-CimInstance -Namespace root\rsop\User\$SID -Query "select * from RSOP_GPLink" -CimSession $CimSession 2>$Null
                                Remove-CimSession $CIMSession
                            }
                            else {
                                $UserPolicies = Get-CimInstance -Namespace root\rsop\User\$SID -Query "select * from RSOP_GPO" -ComputerName $Computer 2>$Null
                                $UserTimes = Get-CimInstance -Namespace root\rsop\User\$SID -Query "select * from RSOP_ExtensionStatus" -ComputerName $Computer 2>$Null
                                $UserGPLink = Get-CimInstance -Namespace root\rsop\User\$SID -Query "select * from RSOP_GPLink" -ComputerName $Computer 2>$Null
                            }
                        }    
                    }
                    else {
                        if ($PSBoundParameters.ContainsKey('Credential')) {
                            $CimSession = New-CimSession -ComputerName $Computer -Credential $Credential
                            $returns = Get-CimInstance -Namespace root\rsop\Computer -Query "select * from RSOP_GPO" -CimSession $CimSession
                            $returnLinks = Get-CimInstance -Namespace root\rsop\Computer -Query "select * from RSOP_GPLink" -CimSession $CimSession
                            Remove-CimSession -CimSession $CimSession 
                        }
                        else {
                            $returns = Get-CimInstance -Namespace root\rsop\Computer -Query "select * from RSOP_GPO" -ComputerName $Computer
                            $returnLinks = Get-CimInstance -Namespace root\rsop\Computer -Query "select * from RSOP_GPLink" -ComputerName $Computer
                        }
                    }                    
                }
                Catch {
                    Write-Warning "Failed to capture group policy information."
                    break
                }  
            }  
            #We test our return information
            if ($PSBoundParameters.ContainsKey('Username')) {
                if ($null -ne $SID) {
                    foreach ($UserPolicy in $UserPolicies) {
                        $Link = $UserGPLink | Where-Object { $_.gpo.id -like $UserPolicy.id }
                        if ($null -ne $link) {
                            $SomOrder = $link.somOrder
                            $AppliedOrdered = $link.appliedOrder
                            $LinkedOrder = $link.linkorder
                            $NoOverride = $link.noOverride
                        }
                        else {
                            $SomOrder = $null
                            $AppliedOrdered = $null
                            $LinkedOrder = $null
                            $NoOverride = $null
                        }
                        $Temp = $UserTimes | Where-Object { $_.extensionGuid -like "*$($UserPolicy.extensionIds[0])*" }
                        try {
                            $TotalTime = ($temp.endtime - $temp.begintime).totalmilliseconds
                        }
                        catch {
                            $TotalTime = '0'
                        }
                        if ($null -ne $Temp) {
                            $Errors = $Temp.error
                            $TotalTime = $TotalTime
                        }
                        else {
                            $Errors = ""
                            $TotalTime = $TotalTime
                        }                  
                        [pscustomobject]@{
                            ComputerName      = $UserPolicy.PSComputerName
                            Username          = $username
                            Name              = $UserPolicy.name
                            Enabled           = $UserPolicy.enabled
                            AccessDenied      = $UserPolicy.accessDenied
                            TotalMilliseconds = $TotalTime
                            Errors            = $Errors
                            SomOrder          = $SomOrder
                            AppliedOrder      = $AppliedOrdered
                            LinkOrder         = $LinkedOrder
                            NoOverride        = $NoOverride
                        }
                    }
                }
            }
            else {
                if (($null -ne $returns) -or ($null -ne $returnLinks)) {
                    foreach ($Return in $returns) {
                        $TempLink = $returnLinks | Where-Object { $_.gpo.id -like $return.id }
                        [PSCustomObject]@{
                            ComputerName = $Computer
                            GPOName      = $Return.name 
                            Enabled      = $TempLink.enabled
                            LinkOrder    = $TempLink.linkOrder
                            SomOrder     = $templink.somOrder
                        }
                    }
                }
                else {
                    Write-Warning "No Information was gathered for $Computer"
                }
            }
            
        }
        else {
            Write-Warning "$Computer Offline"
        }
    }   
}
function Get-SHDComputerHardDrives {
    [cmdletbinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Provide the target hostname",
            Mandatory = $true)][Alias('Hostname', 'cn')][String[]]$Computername,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )
    foreach ($Computer in $Computername) {
        if (Test-Connection -ComputerName $computer -Count 1 -Quiet) {
            try {
                if ($PSBoundParameters.ContainsKey('Credential')) {
                    $cimsession = New-CimSession -ComputerName $Computer -Credential $Credential
                    Get-CimInstance -ClassName Win32_DiskDrive -CimSession $cimsession | ForEach-Object {
                        $disk = $_
                        $partitions = "ASSOCIATORS OF " +
                        "{Win32_DiskDrive.DeviceID='$($disk.DeviceID)'} " +
                        "WHERE AssocClass = Win32_DiskDriveToDiskPartition"
                        Get-CimInstance -Query $partitions -CimSession $cimsession | ForEach-Object {
                            $partition = $_
                            $drives = "ASSOCIATORS OF " +
                            "{Win32_DiskPartition.DeviceID='$($partition.DeviceID)'} " +
                            "WHERE AssocClass = Win32_LogicalDiskToPartition"
                            Get-CimInstance -Query $drives -CimSession $cimsession | ForEach-Object {
                                [pscustomobject]@{
                                    Computername = $Disk.PSComputerName
                                    Disk         = $disk.DeviceID
                                    DiskModel    = $disk.Model
                                    MediaType    = $Disk.MediaType
                                    Firmware     = $Disk.FirmwareRevision
                                    Partition    = $partition.Name
                                    DriveLetter  = $_.DeviceID
                                    VolumeName   = $_.VolumeName
                                    RawSize      = "$([math]::Round($disk.Size/1gb))/gb"
                                    DiskSize     = "$([math]::Round($Partition.Size/1gb))/gb"
                                    FreeSpace    = "$([math]::Round($_.FreeSpace/1gb))/gb"
                                    PercentFree  = "$([math]::Round((($_.FreeSpace/$Partition.Size)*100),2))%"
                                } 
                            }
                        }
                    }
                    Remove-CimSession $cimsession
                }
                else {
                    Get-CimInstance -ClassName Win32_DiskDrive -ComputerName $Computer | ForEach-Object {
                        $disk = $_
                        $partitions = "ASSOCIATORS OF " +
                        "{Win32_DiskDrive.DeviceID='$($disk.DeviceID)'} " +
                        "WHERE AssocClass = Win32_DiskDriveToDiskPartition"
                        Get-CimInstance -Query $partitions -ComputerName $Computer | ForEach-Object {
                            $partition = $_
                            $drives = "ASSOCIATORS OF " +
                            "{Win32_DiskPartition.DeviceID='$($partition.DeviceID)'} " +
                            "WHERE AssocClass = Win32_LogicalDiskToPartition"
                            Get-CimInstance -Query $drives -ComputerName $Computer | ForEach-Object {
                                [pscustomobject]@{
                                    Computername = $Disk.PSComputerName
                                    Disk         = $disk.DeviceID
                                    DiskModel    = $disk.Model
                                    MediaType    = $Disk.MediaType
                                    Firmware     = $Disk.FirmwareRevision
                                    Partition    = $partition.Name
                                    DriveLetter  = $_.DeviceID
                                    VolumeName   = $_.VolumeName
                                    RawSize      = "$([math]::Round($disk.Size/1gb))/gb"
                                    DiskSize     = "$([math]::Round($Partition.Size/1gb))/gb"
                                    FreeSpace    = "$([math]::Round($_.FreeSpace/1gb))/gb"
                                    PercentFree  = "$([math]::Round((($_.FreeSpace/$Partition.Size)*100),2))%"
                                } 
                            }
                        }
                    }
                }
            }
            catch {
                try {
                    if ($PSBoundParameters.ContainsKey('Credential')) {
                        Get-WmiObject -class Win32_DiskDrive -ComputerName $Computer -Credential $Credential | ForEach-Object {
                            $disk = $_
                            $partitions = "ASSOCIATORS OF " +
                            "{Win32_DiskDrive.DeviceID='$($disk.DeviceID)'} " +
                            "WHERE AssocClass = Win32_DiskDriveToDiskPartition"
                            Get-WmiObject -Query $partitions -ComputerName $Computer -Credential $Credential | ForEach-Object {
                                $partition = $_
                                $drives = "ASSOCIATORS OF " +
                                "{Win32_DiskPartition.DeviceID='$($partition.DeviceID)'} " +
                                "WHERE AssocClass = Win32_LogicalDiskToPartition"
                                Get-WmiObject -Query $drives -ComputerName $Computer -Credential $Credential | ForEach-Object {
                                    $TheDrive = [pscustomobject][ordered]@{
                                        Computername = $Disk.PSComputerName
                                        Disk         = $disk.DeviceID
                                        DiskModel    = $disk.Model
                                        MediaType    = $Disk.MediaType
                                        Firmware     = $Disk.FirmwareRevision
                                        Partition    = $partition.Name
                                        DriveLetter  = $_.DeviceID
                                        VolumeName   = $_.VolumeName
                                        RawSize      = "$([math]::Round($disk.Size/1gb))/gb"
                                        DiskSize     = "$([math]::Round($Partition.Size/1gb))/gb"
                                        FreeSpace    = "$([math]::Round($_.FreeSpace/1gb))/gb"
                                        PercentFree  = "$([math]::Round((($_.FreeSpace/$Partition.Size)*100),2))%"
                                    }
                                    $TheDrive 
                                }
                            }
                        }
                    }
                    else {
                        Get-WmiObject -class Win32_DiskDrive -ComputerName $Computer | ForEach-Object {
                            $disk = $_
                            $partitions = "ASSOCIATORS OF " +
                            "{Win32_DiskDrive.DeviceID='$($disk.DeviceID)'} " +
                            "WHERE AssocClass = Win32_DiskDriveToDiskPartition"
                            Get-WmiObject -Query $partitions -ComputerName $Computer | ForEach-Object {
                                $partition = $_
                                $drives = "ASSOCIATORS OF " +
                                "{Win32_DiskPartition.DeviceID='$($partition.DeviceID)'} " +
                                "WHERE AssocClass = Win32_LogicalDiskToPartition"
                                Get-WmiObject -Query $drives -ComputerName $Computer | ForEach-Object {
                                    [pscustomobject]@{
                                        Computername = $Disk.PSComputerName
                                        Disk         = $disk.DeviceID
                                        DiskModel    = $disk.Model
                                        MediaType    = $Disk.MediaType
                                        Firmware     = $Disk.FirmwareRevision
                                        Partition    = $partition.Name
                                        DriveLetter  = $_.DeviceID
                                        VolumeName   = $_.VolumeName
                                        RawSize      = "$([math]::Round($disk.Size/1gb))/gb"
                                        DiskSize     = "$([math]::Round($Partition.Size/1gb))/gb"
                                        FreeSpace    = "$([math]::Round($_.FreeSpace/1gb))/gb"
                                        PercentFree  = "$([math]::Round((($_.FreeSpace/$Partition.Size)*100),2))%"
                                    }
                                }
                            }
                        }
                    }
                }
                catch {
                    Write-Warning "We could not capture data from $Computer"
                }
            }
        }
        else { write-warning "$Computer is offline." }
    }
} #Review - Testing, Documentation
function Get-SHDComputerHotfix {
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
function Get-SHDComputerInfo {
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
                    $ComputerSystem = Get-CimInstance -ClassName win32_ComputerSystem -CimSession $CIMSession
                    $ComputerProcess = Get-CimInstance -ClassName win32_process -CimSession $CIMSession
                    $ComputerOS = Get-CimInstance -ClassName Win32_OperatingSystem -CimSession $CIMSession
                    $ComputerBIOS = Get-CimInstance -ClassName win32_bios -CimSession $CIMSession
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
                    $ComputerSystem = Get-CimInstance -ClassName win32_ComputerSystem -ComputerName $Computer
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
function Get-SHDComputerKeyboard {
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
                    Get-CimInstance -ClassName Win32_Keyboard -CimSession $CIMSession | Select-Object SystemName, Name, Status, DeviceID
                    Remove-CimSession $CIMSession
                }
                else {
                    Get-CimInstance -ClassName Win32_Keyboard -ComputerName $Computer | Select-Object SystemName, Name, Status, DeviceID
                }
            }
            catch {
                try {
                    if ($PSBoundParameters.ContainsKey('Credential')) {
                        Get-WmiObject -Class Win32_Keyboard -computername $Computer -credential $Credential | Select-Object SystemName, Name, Status, DeviceID
                    }
                    else {
                        Get-WmiObject -Class win32_keyboard -computername $Computer | Select-Object SystemName, Name, Status, DeviceID
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
function Get-SHDComputerLocalAccounts {
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
                    $CIMInstance = New-CimSession -ComputerName $computer -Credential $Credential
                    #win32_userprofile
                    Get-CimInstance -ClassName win32_UserAccount -CimSession $CIMInstance | Where-Object { $_.domain -notlike "*tbc*" } | Sort-Object name | Select-Object pscomputername, domain, name
                    Remove-CimSession $CIMInstance
                }
                else {
                    Get-CimInstance -ClassName win32_UserAccount -ComputerName $COmputer | Where-Object { $_.domain -notlike "*tbc*" } | Sort-Object name | Select-Object pscomputername, domain, name
                }
            }
            catch {
                try {
                    if ($PSBoundParameters.ContainsKey('Credential')) {
                        Get-WmiObject -ComputerName $Computer -credential $Credential -Class win32_UserAccount | Where-Object { $_.domain -notlike "*tbc*" } | Sort-Object Name | Select-Object pscomputername, domain, name
                    }
                    else {
                        Get-WmiObject -ComputerName $Computer -Class win32_UserAccount | Where-Object { $_.domain -notlike "*tbc*" } | Sort-Object name | Select-Object pscomputername, domain, name
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
function Get-SHDComputerLocalGroups {
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
                    invoke-command -ComputerName $computer -Credential $Credential -ScriptBlock {
                        Get-LocalGroup
                    }
                }
                else {
                    invoke-command -ComputerName $computer -ScriptBlock {
                        Get-LocalGroup
                    }
                }
            }
            catch {
                Write-Warning "Unable to capture Data from $Computer."
            }
        }
        else {
            Write-Warning "$Computer is offline."
        }
    }
} #Review - Testing, Documentation
function Get-SHDComputerLocalGroupMembers {
    [cmdletbinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Provide the target hostname",
            Mandatory = $true)][Alias('Hostname', 'cn')][String[]]$Computername,
        [Parameter(HelpMessage = "Group Name", Mandatory = $True)][string[]]$GroupName,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )
    foreach ($computer in $Computername) {
        if (Test-Connection -ComputerName $computer -Count 1 -Quiet) {
            foreach ($group in $GroupName) {
                try {
                    if ($PSBoundParameters.ContainsKey('Credential')) {
                        invoke-command -ComputerName $computer -Credential $Credential -ScriptBlock {
                            Get-LocalGroupMember -Group $args[0]
                        } -ArgumentList $Group | Select-Object PScomputername, ObjectClass, name, principalsource
                    }
                    else {
                        invoke-command -ComputerName $computer -ScriptBlock {
                            Get-LocalGroupMember -Group $args[0]
                        } -ArgumentList $Group | Select-Object PScomputername, ObjectClass, name, principalsource
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
function Get-SHDComputerLogicalFixedDrives {
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
                    $CIMSession = New-CimSession -ComputerName $computer -Credential $Credential
                    $Logicaldisk = Get-CimInstance -ClassName win32_logicaldisk -CimSession $CIMSession | Select-Object *
                    $Logicaldisk | Where-Object { $_.drivetype -eq 3 } | Select-Object -Property @(
                        @{Label = "Caption"; Expression = { $_.caption } }
                        @{Label = "Description"; Expression = { $_.Description } }
                        @{Label = "FileSystem"; Expression = { $_.Filesystem } }
                        @{Label = "FreeSpace"; Expression = { [math]::Round($_.freespace/1gb) } }
                        @{Label = "TotalDiskSpace"; Expression = { [math]::Round($_.size/1gb) } }
                    ) # End Return
                    Remove-CimSession $CIMSession
                }
                else {
                    $Logicaldisk = Get-CimInstance -ClassName win32_logicaldisk -ComputerName $computer | Select-Object *
                    $Logicaldisk | Where-Object { $_.drivetype -eq 3 } | Select-Object -Property @(
                        @{Label = "Caption"; Expression = { $_.caption } }
                        @{Label = "Description"; Expression = { $_.Description } }
                        @{Label = "FileSystem"; Expression = { $_.Filesystem } }
                        @{Label = "FreeSpace"; Expression = { [math]::Round($_.freespace/1gb) } }
                        @{Label = "TotalDiskSpace"; Expression = { [math]::Round($_.size/1gb) } }
                    ) # End Return
                }
            }
            catch {
                try {
                    if ($PSBoundParameters.ContainsKey('Credential')) {
                        $Logicaldisk = Get-WmiObject -Class win32_logicaldisk -ComputerName $Computer -credential $Credential | Select-Object *
                        $Logicaldisk | Where-Object { $_.drivetype -eq 3 } | Select-Object -Property @(
                            @{Label = "Caption"; Expression = { $_.caption } }
                            @{Label = "Description"; Expression = { $_.Description } }
                            @{Label = "FileSystem"; Expression = { $_.Filesystem } }
                            @{Label = "FreeSpace"; Expression = { [math]::Round($_.freespace/1gb) } }
                            @{Label = "TotalDiskSpace"; Expression = { [math]::Round($_.size/1gb) } }
                        ) # End Return
                    }
                    else {
                        $Logicaldisk = Get-WmiObject -Class win32_logicaldisk -ComputerName $Computer | Select-Object *
                        $Logicaldisk | Where-Object { $_.drivetype -eq 3 } | Select-Object -Property @(
                            @{Label = "Caption"; Expression = { $_.caption } }
                            @{Label = "Description"; Expression = { $_.Description } }
                            @{Label = "FileSystem"; Expression = { $_.Filesystem } }
                            @{Label = "FreeSpace"; Expression = { [math]::Round($_.freespace/1gb) } }
                            @{Label = "TotalDiskSpace"; Expression = { [math]::Round($_.size/1gb) } }
                        ) # End Return
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
} #Review - Testing,Documentation
function Get-SHDComputerLogicalNetworkDrives {
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
                    $Logicaldisk = Get-WmiObject -Class win32_logicaldisk -CimSession $CIMSession | Select-Object *
                    $Logicaldisk | Where-Object { $_.drivetype -eq 4 } | Select-Object -Property @(
                        @{Label = "Caption"; Expression = { $_.caption } }
                        @{Label = "Description"; Expression = { $_.Description } }
                        @{Label = "FileSystem"; Expression = { $_.Filesystem } }
                        @{Label = "FreeSpace"; Expression = { [math]::Round($_.freespace/1gb) } }
                        @{Label = "TotalDiskSpace"; Expression = { [math]::Round($_.size/1gb) } }
                    ) # End Return
                    Remove-CimSession
                }
                else {
                    $Logicaldisk = Get-CimInstance -Class win32_logicaldisk -ComputerName $Computer | Select-Object *
                    $Logicaldisk | Where-Object { $_.drivetype -eq 4 } | Select-Object -Property @(
                        @{Label = "Caption"; Expression = { $_.caption } }
                        @{Label = "Description"; Expression = { $_.Description } }
                        @{Label = "FileSystem"; Expression = { $_.Filesystem } }
                        @{Label = "FreeSpace"; Expression = { [math]::Round($_.freespace/1gb) } }
                        @{Label = "TotalDiskSpace"; Expression = { [math]::Round($_.size/1gb) } }
                    ) # End Return
                }
            }
            catch {
                try {
                    if ($PSBoundParameters.ContainsKey('Credential')) {
                        $Logicaldisk = Get-WmiObject -Class win32_logicaldisk -ComputerName $Computer -credential $Credential | Select-Object *
                        $Logicaldisk | Where-Object { $_.drivetype -eq 4 } | Select-Object -Property @(
                            @{Label = "Caption"; Expression = { $_.caption } }
                            @{Label = "Description"; Expression = { $_.Description } }
                            @{Label = "FileSystem"; Expression = { $_.Filesystem } }
                            @{Label = "FreeSpace"; Expression = { [math]::Round($_.freespace/1gb) } }
                            @{Label = "TotalDiskSpace"; Expression = { [math]::Round($_.size/1gb) } }
                        ) # End Return
                    }
                    else {
                        $Logicaldisk = Get-WmiObject -Class win32_logicaldisk -ComputerName $Computer | Select-Object *
                        $Logicaldisk | Where-Object { $_.drivetype -eq 4 } | Select-Object -Property @(
                            @{Label = "Caption"; Expression = { $_.caption } }
                            @{Label = "Description"; Expression = { $_.Description } }
                            @{Label = "FileSystem"; Expression = { $_.Filesystem } }
                            @{Label = "FreeSpace"; Expression = { [math]::Round($_.freespace/1gb) } }
                            @{Label = "TotalDiskSpace"; Expression = { [math]::Round($_.size/1gb) } }
                        ) # End Return
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
function Get-SHDComputerLogicalRemovableDrives {
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
                    $Logicaldisk = Get-CimInstance -ClassName win32_logicaldisk -CimSession $CIMSession | Select-Object *
                    $Logicaldisk | Where-Object { $_.drivetype -eq 2 } | Select-Object -Property @(
                        @{Label = "Caption"; Expression = { $_.caption } }
                        @{Label = "Description"; Expression = { $_.Description } }
                        @{Label = "FileSystem"; Expression = { $_.Filesystem } }
                        @{Label = "FreeSpace"; Expression = { [math]::Round($_.freespace/1gb) } }
                        @{Label = "TotalDiskSpace"; Expression = { [math]::Round($_.size/1gb) } }
                    )
                    Remove-CimSession $CIMSession
                }
                else {
                    $Logicaldisk = Get-CimInstance -ClassName win32_logicaldisk -ComputerName $computer | Select-Object *
                    $Logicaldisk | Where-Object { $_.drivetype -eq 2 } | Select-Object -Property @(
                        @{Label = "Caption"; Expression = { $_.caption } }
                        @{Label = "Description"; Expression = { $_.Description } }
                        @{Label = "FileSystem"; Expression = { $_.Filesystem } }
                        @{Label = "FreeSpace"; Expression = { [math]::Round($_.freespace/1gb) } }
                        @{Label = "TotalDiskSpace"; Expression = { [math]::Round($_.size/1gb) } }
                    )
                }
            }
            catch {
                try {
                    if ($PSBoundParameters.ContainsKey('Credential')) {
                        $Logicaldisk = Get-WmiObject -Class win32_logicaldisk -ComputerName $Computer -credential $Credential | Select-Object *
                        $Logicaldisk | Where-Object { $_.drivetype -eq 2 } | Select-Object -Property @(
                            @{Label = "Caption"; Expression = { $_.caption } }
                            @{Label = "Description"; Expression = { $_.Description } }
                            @{Label = "FileSystem"; Expression = { $_.Filesystem } }
                            @{Label = "FreeSpace"; Expression = { [math]::Round($_.freespace/1gb) } }
                            @{Label = "TotalDiskSpace"; Expression = { [math]::Round($_.size/1gb) } }
                        )
                    }
                    else {
                        $Logicaldisk = Get-WmiObject -Class win32_logicaldisk -ComputerName $computer | Select-Object *
                        $Logicaldisk | Where-Object { $_.drivetype -eq 2 } | Select-Object -Property @(
                            @{Label = "Caption"; Expression = { $_.caption } }
                            @{Label = "Description"; Expression = { $_.Description } }
                            @{Label = "FileSystem"; Expression = { $_.Filesystem } }
                            @{Label = "FreeSpace"; Expression = { [math]::Round($_.freespace/1gb) } }
                            @{Label = "TotalDiskSpace"; Expression = { [math]::Round($_.size/1gb) } }
                        )
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
function Get-SHDComputerMacAddresses {
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
                    $CimSession = New-CimSession -ComputerName $Computer -Credential $Credential
                    Get-CimInstance -ClassName win32_networkadapter -CimSession $CimSession | Where-Object { $null -ne $_.macaddress } | Select-Object PSComputername, name, macaddress
                    Remove-CimSession -CimSession $CimSession
                }
                else {
                    Get-CimInstance -ClassName win32_networkadapter -ComputerName $Computer | Where-Object { $null -ne $_.macaddress } | Select-Object PSComputername, name, macaddress
                }
            }
            catch {
                try {
                    if ($PSBoundParameters.ContainsKey('Credential')) {
                        get-wmiobject -Class win32_networkadapter -ComputerName $computerName -credential $Credential | Where-Object { $null -ne $_.macaddress } | Select-Object PSComputername, name, macaddress
                    }
                    else {
                        get-wmiobject -Class win32_networkadapter -ComputerName $computerName | Where-Object { $null -ne $_.macaddress } | Select-Object PSComputername, name, macaddress
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
function Get-SHDComputerMacAddressVendor {
    [cmdletbinding()]
    param (
        [parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "The Mac Address to validate and find vendor information for.",
            Mandatory = $true
        )][Alias('PhysicalAddress', 'PhysicalLayerAddress')]
        [ValidatePattern("^([0-9A-Fa-f]{2}[:-,_.]){5}([0-9A-Fa-f]{2})$")][string]$MacAddress
    )
    [pscustomobject]@{
        MacAddress = $MacAddress
        Vendor     = (Invoke-WebRequest -Uri "https://api.macvendors.com/$($MacAddress)" -UseBasicParsing -DisableKeepAlive).Content
    }
} #Review - Testing, Documentation
function Get-SHDComputerMemoryLoad {
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
                    $Memory = invoke-command -ComputerName $computer -Credential $Credential -ScriptBlock {
                        Get-Counter -Counter "\Memory\% Committed Bytes In Use" -SampleInterval 2 -MaxSamples 5
                    }
                }
                else {
                    $Memory = Get-Counter -ComputerName $computer -Counter "\Memory\% Committed Bytes In Use" -SampleInterval 2 -MaxSamples 5
                }
            }
            catch {
                Write-Warning "Unable to access data from $Computer"
            }
            if ($null -ne $Memory) {
                $Load = ($Memory.CounterSamples.CookedValue | Measure-Object -Average).Average
                [PSCustomObject]@{
                    ComputerName = $Computer
                    Memory       = $Load
                }
            }
        }
        else {
            Write-Warning "$Computer is offline."
        }
    }
} #Review - Testing, Documentation
function Get-SHDComputerMonitors {
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
                    $ComputerDesktop = Get-CimInstance -class Win32_DesktopMonitor  -CimSession $CIMSession | Select-Object *
                    foreach ($Screen in $ComputerDesktop) {
                        [pscustomobject]@{
                            ComputerName = $Screen.PSComputerName
                            MonitorID    = $Screen.DeviceID
                            MakeModel    = $Screen.MonitorType
                            Height       = $Screen.ScreenHeight
                            width        = $Screen.screenwidth
                            Description  = $Screen.Description
                        }
                    }
                    Remove-CimSession -CimSession $CIMSession
                }
                else {
                    $ComputerDesktop = Get-CimInstance -class Win32_DesktopMonitor -ComputerName $Computer | Select-Object *
                    foreach ($Screen in $ComputerDesktop) {
                        [pscustomobject]@{
                            ComputerName = $Screen.PSComputerName
                            MonitorID    = $Screen.DeviceID
                            MakeModel    = $Screen.MonitorType
                            Height       = $Screen.ScreenHeight
                            width        = $Screen.screenwidth
                            Description  = $Screen.Description
                        }
                    }
                }
            }
            catch {
                try {
                    if ($PSBoundParameters.ContainsKey('Credential')) {
                        $ComputerDesktop = get-wmiobject -class Win32_DesktopMonitor -ComputerName $Computer -credential $Credential | Select-Object *
                        foreach ($Screen in $ComputerDesktop) {
                            [pscustomobject]@{
                                ComputerName = $Screen.PSComputerName
                                MonitorID    = $Screen.DeviceID
                                MakeModel    = $Screen.MonitorType
                                Height       = $Screen.ScreenHeight
                                width        = $Screen.screenwidth
                                Description  = $Screen.Description
                            }
                        }
                    }
                    else {
                        $ComputerDesktop = get-wmiobject -class Win32_DesktopMonitor -ComputerName $Computer | Select-Object *
                        foreach ($Screen in $ComputerDesktop) {
                            [pscustomobject]@{
                                ComputerName = $Screen.PSComputerName
                                MonitorID    = $Screen.DeviceID
                                MakeModel    = $Screen.MonitorType
                                Height       = $Screen.ScreenHeight
                                width        = $Screen.screenwidth
                                Description  = $Screen.Description
                            }
                        }
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
} #Review Testing, Documentation
function Get-SHDComputerMotherBoard {
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
                    $CIMSession = New-CimSession -ComputerName $computer -Credential $Credential
                    Get-CimInstance -Class win32_baseboard -CimSession $CIMSession | Select-Object PSComputerName, Manufacturer, Product, Removable, Replaceable, SerialNumber, version 
                    Remove-CimSession $CIMSession
                }
                else {
                    Get-CimInstance -ClassName win32_baseboard -computername $Computer | Select-Object PSComputerName, Manufacturer, Product, Removable, Replaceable, SerialNumber, version 
                }
            }
            catch {
                try {
                    if ($PSBoundParameters.ContainsKey('Credential')) {
                        Get-WmiObject -Class win32_baseboard -computername $Computer -credential $Credential | Select-Object PSComputerName, Manufacturer, Product, Removable, Replaceable, SerialNumber, version 
                    }
                    else {
                        Get-WmiObject -Class win32_baseboard -computername $Computer | Select-Object PSComputerName, Manufacturer, Product, Removable, Replaceable, SerialNumber, version 
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
} #Review Testing, Documentation
function Get-SHDComputerName {
    <#
		.SYNOPSIS
		    Searches DNS for computername then looks at active directory for computer names. 
		.DESCRIPTION
            Searches DNS for computername then looks at active directory for computer names. 
		.PARAMETER ComputerName
            The Computername you are looking for. You can use part of the name to help find the name.
		.PARAMETER Online
		    Scans wither the name is online. 
		.EXAMPLE
		    PS C:\> Get-SHDComputerName 'whatthecrap','ohmyyall','cats','stem' -Online

            ComputerName   IPV4         IPV6
            ------------   ----         ----
            Laptop-STEM1   10.10.1.2      
            Server-STEM1   10.10.1.3      
            Server-STEM2   10.10.1.4     
            Server-STEM3   10.10.1.5     
            Desktop-STEM1  10.10.1.6      
            Desktop-STEM2  10.10.1.7     
            
            Searches DNS and AD for any computer with the names listed. Then it pings the computer.            
		.LINK
		    https://bolding.us
		.NOTES
            Author: David Bolding
            Site: https://www.bolding.us
	#>
    [cmdletbinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName = $true, Mandatory = $true)][string[]]$ComputerName,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential,
        [switch]$Online
    )
    foreach ($Computer in $ComputerName) {
        $Computers = $null
        try {
            if ($PSBoundParameters.ContainsKey('Credential')) {
                $Domain = Get-ADDomain -Credential $Credential | Select-Object *
                $cimsession = New-CimSession -ComputerName $Domain.pdcemulator -Credential $Credential
                $Computers = (Get-DnsServerResourceRecord -CimSession $cimsession -ComputerName $Domain.pdcemulator -ZoneName $Domain.DNSroot | Where-Object { $_.hostname -like "*$Computer*" }).hostname
                Remove-CimSession -CimSession $cimsession
            }
            else {
                $Domain = (Get-ADDomain).pdcemulator
                $DNSRoot = (Get-ADDomain).DNSRoot
                $Computers = (Get-DnsServerResourceRecord -ComputerName $Domain -ZoneName $DNSRoot | Where-Object { $_.hostname -like "*$Computer*" }).hostname
            }
            
        }
        catch {
            try {
                if ($PSBoundParameters.ContainsKey('Credential')) {
                    $Computers = (Get-ADComputer -Filter { name -like "*$Computer*" } -Credential $Credential).name    
                }
                else {
                    $Computers = (Get-ADComputer -Filter { name -like "*$Computer*" }).name    
                }
            }
            catch {
                Write-Warning "Unable to find $Computer"
            }
        }
        if ($null -ne $Computers) {
            if ($Online) {
                foreach ($PC in $Computers) {
                    $NetworkInfo = Test-Connection -ComputerName $PC -Count 1 -ErrorAction SilentlyContinue
                    $Temp = [pscustomobject][ordered]@{
                        ComputerName = $PC
                        IPV4         = $NetworkInfo.IPV4Address.IPAddressToString
                        IPV6         = $NetworkInfo.IPV6Address.IPAddressToString
                    }
                    $Temp
                }
            }
            else {
                $Computers
            }
        }
        else {
            Write-Warning "$Computer Not Found"
        }
    }
} #Review -documetation
function Get-SHDComputerNetworkAdapters {
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
                    Get-CimInstance -Class win32_networkadapterconfiguration -CimSession $CIMSession | Where-Object { $null -ne $_.macaddress } | Select-Object PScomputername, DNSDomainSuffixSearchOrder, Description, DHCPEnabled, DHCPServer, IPAddress, DNSServerSearchOrder, DefaultIPGateway, IPSubnet, MACAddress
                    Remove-CimSession $CIMSession
                }
                else {
                    Get-CimInstance -ClassName win32_networkadapterconfiguration -ComputerName $computer | Where-Object { $null -ne $_.macaddress } | Select-Object PScomputername, DNSDomainSuffixSearchOrder, Description, DHCPEnabled, DHCPServer, IPAddress, DNSServerSearchOrder, DefaultIPGateway, IPSubnet, MACAddress
                }
            }
            catch {
                try {
                    if ($PSBoundParameters.ContainsKey('Credential')) {
                        get-wmiobject -Class win32_networkadapterconfiguration -ComputerName $Computer -credential $Credential | Where-Object { $null -ne $_.macaddress } | Select-Object PScomputername, DNSDomainSuffixSearchOrder, Description, DHCPEnabled, DHCPServer, IPAddress, DNSServerSearchOrder, DefaultIPGateway, IPSubnet, MACAddress
                    }
                    else {
                        get-wmiobject -Class win32_networkadapterconfiguration -ComputerName $Computer | Where-Object { $null -ne $_.macaddress } | Select-Object PScomputername, DNSDomainSuffixSearchOrder, Description, DHCPEnabled, DHCPServer, IPAddress, DNSServerSearchOrder, DefaultIPGateway, IPSubnet, MACAddress
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
function Get-SHDComputerOS {
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
                    $ComputerOS = Get-CimInstance -CimSession $CIMSession -ClassName Win32_OperatingSystem                    
                    Remove-CimSession $CIMSession
                    $ADInfo = Get-ADComputer -Identity $computer -Credential $Credential
                    [PSCustomObject]@{
                        ComputerName = $Computer
                        OS           = $ComputerOS.Caption
                        BuildNumber  = $ComputerOS.BuildNumber
                        Arch         = $Computeros.OSArchitecture
                        InstallDate  = $ComputerOS.InstallDate
                        LocalTime    = $Computeros.LocalDateTime
                        SerialNumber = $ComputerOS.SerialNumber
                        AdminUser    = $ComputerOS.RegisteredUser
                        AddedToAD    = $ADInfo.CreateTimeStamp
                        SID          = $ADInfo.SID
                        EnabledInAD  = $ADInfo.Enabled
                    }
                }
                else {
                    $ComputerOS = Get-CimInstance -ComputerName $Computer -ClassName Win32_OperatingSystem                    
                    $ADInfo = Get-ADComputer -Identity $computer
                    [PSCustomObject]@{
                        ComputerName = $Computer
                        OS           = $ComputerOS.Caption
                        BuildNumber  = $ComputerOS.BuildNumber
                        Arch         = $Computeros.OSArchitecture
                        InstallDate  = $ComputerOS.InstallDate
                        LocalTime    = $Computeros.LocalDateTime
                        SerialNumber = $ComputerOS.SerialNumber
                        AdminUser    = $ComputerOS.RegisteredUser
                        AddedToAD    = $ADInfo.CreateTimeStamp
                        SID          = $ADInfo.SID
                        EnabledInAD  = $ADInfo.Enabled
                    }
                }
            }
            catch {
                try {
                    if ($PSBoundParameters.ContainsKey('Credential')) {
                        $ComputerOS = Get-Wimobject -Credential $Credential -ComputerName $Computer -Class Win32_OperatingSystem                    
                        $ADInfo = Get-ADComputer -Identity $computer -Credential $Credential
                        [PSCustomObject]@{
                            ComputerName = $Computer
                            OS           = $ComputerOS.Caption
                            BuildNumber  = $ComputerOS.BuildNumber
                            Arch         = $Computeros.OSArchitecture
                            InstallDate  = $ComputerOS.InstallDate
                            LocalTime    = $Computeros.LocalDateTime
                            SerialNumber = $ComputerOS.SerialNumber
                            AdminUser    = $ComputerOS.RegisteredUser
                            AddedToAD    = $ADInfo.CreateTimeStamp
                            SID          = $ADInfo.SID
                            EnabledInAD  = $ADInfo.Enabled
                        }
                    }
                    else {
                        $ComputerOS = Get-Wimobject -ComputerName $Computer -Class Win32_OperatingSystem                    
                        $ADInfo = Get-ADComputer -Identity $computer
                        [PSCustomObject]@{
                            ComputerName = $Computer
                            OS           = $ComputerOS.Caption
                            BuildNumber  = $ComputerOS.BuildNumber
                            Arch         = $Computeros.OSArchitecture
                            InstallDate  = $ComputerOS.InstallDate
                            LocalTime    = $Computeros.LocalDateTime
                            SerialNumber = $ComputerOS.SerialNumber
                            AdminUser    = $ComputerOS.RegisteredUser
                            AddedToAD    = $ADInfo.CreateTimeStamp
                            SID          = $ADInfo.SID
                            EnabledInAD  = $ADInfo.Enabled
                        }
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
Function Get-SHDComputerPrinters {
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
                    $Printers = Get-Printer -CimSession $CIMSession 
                    foreach ($printer in $Printers) {
                        $Printjobs = Get-PrintJob -CimSession $CIMSession -PrinterName $printer.name 
                        $printConfig = Get-PrintConfiguration -CimSession $CIMSession -PrinterName $printer.name
                        [PScustomobject]@{
                            ComputerName    = $Computer
                            Servername      = $Printer.ComputerName
                            PortName        = $printer.PortName
                            PrinterLocation = $Printer.location
                            PrinterDrivers  = $Printer.Drivername
                            ConnectionType  = $Printer.type
                            Collate         = $PrintConfig.collate 
                            Color           = $PrintConfig.color
                            Duplexingmode   = $PrintConfig.duplexingmode 
                            PrintJobs       = $Printjobs.count 
                        }
                    }
                    Remove-CimSession $CIMSession
                }
                else {
                    $Printers = Get-Printer -ComputerName $Computer 
                    foreach ($printer in $Printers) {
                        $Printjobs = Get-PrintJob -ComputerName $computer -PrinterName $printer.name 
                        $printConfig = Get-PrintConfiguration -ComputerName $Computer -PrinterName $printer.name
                        [PScustomobject]@{
                            ComputerName    = $Computer
                            Servername      = $Printer.ComputerName
                            PortName        = $printer.PortName
                            PrinterLocation = $Printer.location
                            PrinterDrivers  = $Printer.Drivername
                            ConnectionType  = $Printer.type
                            Collate         = $PrintConfig.collate 
                            Color           = $PrintConfig.color
                            Duplexingmode   = $PrintConfig.duplexingmode 
                            PrintJobs       = $Printjobs.count 
                        }
                    }
                }
            }
            catch {
                Write-Warning "Unable to capture Data from $Computer."
            }
        }
        else {
            Write-Warning "$Computer is offline."
        }
    }
} #Review - Testing, Documentation
function Get-SHDComputerProfiles {
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
                    $CIMInstance = New-CimSession -ComputerName $computer -Credential $Credential
                    #win32_userprofile
                    Get-CimInstance -ClassName win32_userprofile -CimSession $CIMInstance | Sort-Object LocalPath | Select-Object @{Label = "ComputerName"; Expression = { $computer } }, @{Label = "Username"; Expression = { $_.LocalPath -replace '.*\\', '' } }, LocalPath, Special, Loaded
                    Remove-CimSession $CIMInstance
                }
                else {
                    Get-CimInstance -ClassName win32_userprofile -ComputerName $COmputer | Sort-Object LocalPath | Select-Object @{Label = "ComputerName"; Expression = { $computer } }, @{Label = "Username"; Expression = { $_.LocalPath -replace '.*\\', '' } }, LocalPath, Special, Loaded
                }
            }
            catch {
                try {
                    if ($PSBoundParameters.ContainsKey('Credential')) {
                        Get-WmiObject -ComputerName $Computer -credential $Credential -Class win32_userprofile | Sort-Object LocalPath | Select-Object @{Label = "ComputerName"; Expression = { $computer } }, @{Label = "Username"; Expression = { $_.LocalPath -replace '.*\\', '' } }, LocalPath, Special, Loaded
                    }
                    else {
                        Get-WmiObject -ComputerName $Computer -Class win32_userprofile | Sort-Object LocalPath | Select-Object @{Label = "ComputerName"; Expression = { $computer } }, @{Label = "Username"; Expression = { $_.LocalPath -replace '.*\\', '' } }, LocalPath, Special, Loaded
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
function Get-SHDComputerPublicIPAddress {
    [cmdletbinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Provide the target hostname",
            Mandatory = $true)][Alias('Hostname', 'cn')][String[]]$Computername,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )
    foreach ($Computer in $Computername) {
        if ($PSBoundParameters.ContainsKey('Credential')) {
            Invoke-Command -computername $Computer -Credential $Credential -ScriptBlock {
                [pscustomobject]@{
                    ComputerName = $args[0]
                    IPAddress    = (Invoke-RestMethod http://ipinfo.io/json -UseBasicParsing -DisableKeepAlive).ip
                }
                
            } -ArgumentList $Computer | Select-Object ComputerName, IPAddress
        }
        else {
            Invoke-Command -computername $Computer -ScriptBlock {
                [pscustomobject]@{
                    ComputerName = $args[0]
                    IPAddress    = (Invoke-RestMethod http://ipinfo.io/json -UseBasicParsing -DisableKeepAlive).ip
                }
            } -ArgumentList $Computer | Select-Object ComputerName, IPAddress
        }
    }
} #Review - Test, Documentation
function Get-SHDComputerRam {
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
                    $ComputerSystem = Get-CimInstance -Class win32_ComputerSystem -CimSession $cimsession | Select-Object *
                    $ComputerOS = Get-CimInstance -Class Win32_OperatingSystem -CimSession $cimsession | Select-Object *
                    [pscustomobject]@{
                        ComputerName = $ComputerSystem.pscomputername
                        RamFree      = [math]::Round($ComputerOS.FreePhysicalMemory/1mb) 
                        RamTotal     = [math]::Round($ComputerSystem.TotalPhysicalMemory/1gb)
                        PercentFree  = "$([math]::Round((($ComputerOS.FreePhysicalMemory/$ComputerSystem.TotalPhysicalMemory) * 100000),2))%"
                    } # End Return Add
                    Remove-CimSession $CIMSession
                }
                else {
                    $ComputerSystem = Get-CimInstance -Class win32_ComputerSystem -ComputerName $Computer | Select-Object *
                    $ComputerOS = Get-CimInstance -Class Win32_OperatingSystem -ComputerName $Computer | Select-Object *
                    [pscustomobject]@{
                        ComputerName = $ComputerSystem.pscomputername
                        RamFree      = [math]::Round($ComputerOS.FreePhysicalMemory/1mb) 
                        RamTotal     = [math]::Round($ComputerSystem.TotalPhysicalMemory/1gb)
                        PercentFree  = "$([math]::Round((($ComputerOS.FreePhysicalMemory/$ComputerSystem.TotalPhysicalMemory) * 100000),2))%"
                    } # End Return Add
                }
            }
            catch {
                try {
                    if ($PSBoundParameters.ContainsKey('Credential')) {
                        $ComputerSystem = Get-WmiObject -Class win32_ComputerSystem -ComputerName $Computer -credential $Credential | Select-Object *
                        $ComputerOS = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Computer -credential $Credential | Select-Object *
                        [pscustomobject]@{
                            ComputerName = $ComputerSystem.pscomputername
                            RamFree      = [math]::Round($ComputerOS.FreePhysicalMemory/1mb) 
                            RamTotal     = [math]::Round($ComputerSystem.TotalPhysicalMemory/1gb)
                            PercentFree  = "$([math]::Round((($ComputerOS.FreePhysicalMemory/$ComputerSystem.TotalPhysicalMemory) * 100000),2))%"
                        } # End Return Add
                    }
                    else {
                        $ComputerSystem = Get-WmiObject -Class win32_ComputerSystem -ComputerName $Computer | Select-Object *
                        $ComputerOS = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Computer | Select-Object *
                        [pscustomobject]@{
                            ComputerName = $ComputerSystem.pscomputername
                            RamFree      = [math]::Round($ComputerOS.FreePhysicalMemory/1mb) 
                            RamTotal     = [math]::Round($ComputerSystem.TotalPhysicalMemory/1gb)
                            PercentFree  = "$([math]::Round((($ComputerOS.FreePhysicalMemory/$ComputerSystem.TotalPhysicalMemory) * 100000),2))%"
                        } # End Return Add
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
function Get-SHDComputerRamChip {
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
                    $ComputerPhysicalMemory = Get-CimInstance -ClassName win32_physicalmemory -CimSession $CIMSession | Select-Object *
                    foreach ($Chip in $ComputerPhysicalMemory) {
                        $Return += [pscustomobject][ordered]@{
                            Computername = $Chip.pscomputername
                            ChipNumber   = $chip.banklabel 
                            Size         = [math]::Round($Chip.capacity/1gb)
                            Speed        = $chip.configuredclockspeed
                            Manufacturer = $chip.manufacturer 
                            PartNumber   = $chip.partnumber 
                            SerialNumber = $chip.serialnumber
                        } # End Return Add
                    } # End Foreach Chip
                    Remove-CimSession $CIMSession
                }
                else {
                    $ComputerPhysicalMemory = Get-CimInstance -Class win32_physicalmemory -ComputerName $Computer | Select-Object *
                    foreach ($Chip in $ComputerPhysicalMemory) {
                        [pscustomobject]@{
                            Computername = $Chip.pscomputername
                            ChipNumber   = $chip.banklabel 
                            Size         = [math]::Round($Chip.capacity/1gb)
                            Speed        = $chip.configuredclockspeed
                            Manufacturer = $chip.manufacturer 
                            PartNumber   = $chip.partnumber 
                            SerialNumber = $chip.serialnumber
                        } # End Return Add
                    } # End Foreach Chip
                }
            }
            catch {
                try {
                    if ($PSBoundParameters.ContainsKey('Credential')) {
                        $ComputerPhysicalMemory = Get-WmiObject -Class win32_physicalmemory -ComputerName $Computer -credential $Credential | Select-Object *
                        foreach ($Chip in $ComputerPhysicalMemory) {
                            [pscustomobject]@{
                                Computername = $Chip.pscomputername
                                ChipNumber   = $chip.banklabel 
                                Size         = [math]::Round($Chip.capacity/1gb)
                                Speed        = $chip.configuredclockspeed
                                Manufacturer = $chip.manufacturer 
                                PartNumber   = $chip.partnumber 
                                SerialNumber = $chip.serialnumber
                            } # End Return Add
                        } # End Foreach Chip
                    }
                    else {
                        $ComputerPhysicalMemory = Get-WmiObject -Class win32_physicalmemory -ComputerName $Computer | Select-Object *
                        foreach ($Chip in $ComputerPhysicalMemory) {
                            [pscustomobject]@{
                                Computername = $Chip.pscomputername
                                ChipNumber   = $chip.banklabel 
                                Size         = [math]::Round($Chip.capacity/1gb)
                                Speed        = $chip.configuredclockspeed
                                Manufacturer = $chip.manufacturer 
                                PartNumber   = $chip.partnumber 
                                SerialNumber = $chip.serialnumber
                            } # End Return Add
                        } # End Foreach Chip
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
Function Get-SHDComputerRegistrySize {
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
                    Get-CimInstance -ClassName Win32_Registry -CimSession $CIMSession | Select-Object @{Label = "ComputerName"; Expression = { $computer } }, CurrentSize, MaximumSize
                    Remove-CimSession $CIMSession
                }
                else {
                    Get-CimInstance -ClassName Win32_Registry -ComputerName $Computer | Select-Object @{Label = "ComputerName"; Expression = { $computer } }, CurrentSize, MaximumSize
                }
            }
            catch {
                try {
                    if ($PSBoundParameters.ContainsKey('Credential')) {
                        Get-WmiObject -ClassName Win32_Registry -ComputerName $Computer -Credential $Credential | Select-Object @{Label = "ComputerName"; Expression = { $computer } }, CurrentSize, MaximumSize
                    }
                    else {
                        Get-WmiObject -ClassName Win32_Registry -ComputerName $Computer | Select-Object @{Label = "ComputerName"; Expression = { $computer } }, CurrentSize, MaximumSize
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
function Get-SHDComputerSCSIControllers {
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
                    Get-CimInstance -ClassName Win32_SCSIController -CimSession $CIMSession
                    Remove-CimSession $CIMSession
                }
                else {
                    Get-CimInstance -ClassName Win32_SCSIController -ComputerName $computer
                }
            }
            catch {
                try {
                    if ($PSBoundParameters.ContainsKey('Credential')) {
                        Get-WmiObject -ClassName Win32_SCSIController -ComputerName $Computer -credential $Credential
                    }
                    else {
                        Get-WmiObject -ClassName Win32_SCSIController -ComputerName $computer
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
function Get-SHDComputerSerialNumber {
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
                    (Get-CimInstance -Class win32_bios -CimSession $CIMSession).serialnumber 
                    Remove-CimSession $CIMSession
                }
                else {
                    (Get-CimInstance -Class win32_bios -ComputerName $Computer).serialnumber 
                }
            }
            catch {
                try {
                    if ($PSBoundParameters.ContainsKey('Credential')) {
                        (Get-WmiObject -Class win32_bios -ComputerName $Computer -Credential $Credential).serialnumber 
                    }
                    else {
                        (Get-WmiObject -Class win32_bios -ComputerName $Computer).serialnumber 
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
function Get-SHDComputerServices {
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
                    Get-CimInstance -ClassName win32_service -CimSession $CIMSession
                    Remove-CimSession $CIMSession
                }
                else {
                    Get-CimInstance -ClassName win32_service -ComputerName $computer
                }
            }
            catch {
                try {
                    if ($PSBoundParameters.ContainsKey('Credential')) {
                        Get-WmiObject -ClassName win32_service -ComputerName $computer -credential $Credential
                    }
                    else {
                        Get-WmiObject -ClassName win32_service -ComputerName $computer 
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
} #review - Testing, Documentation
function Get-SHDComputerShares {
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
                    Get-CimInstance -Class win32_share -CimSession $CIMSession | Select-Object PSComputerName, Name, Path, Description, Status
                    Remove-CimSession $CIMSession
                }
                else {
                    Get-CimInstance -Class win32_share -ComputerName $Computer | Select-Object PSComputerName, Name, Path, Description, Status
                }
            }
            catch {
                try {
                    if ($PSBoundParameters.ContainsKey('Credential')) {
                        Get-WmiObject -Class win32_share -ComputerName $Computer -credential $Credential | Select-Object PSComputerName, Name, Path, Description, Status
                    }
                    else {
                        Get-WmiObject -Class win32_share -ComputerName $Computer | Select-Object PSComputerName, Name, Path, Description, Status
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
function Get-SHDComputerSoftware {
    [cmdletbinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Provide the target hostname",
            Mandatory = $true)][Alias('Hostname', 'cn')][String[]]$Computername,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential,
        [Parameter(
            Helpmessage = "Slow = Product Wmi Object, Fast = Registry Data"
        )][Validateset("Registry", "WMI")][string]$Type = "WMI"
    )
    foreach ($computer in $Computername) {
        if (Test-Connection -ComputerName $computer -Count 1 -Quiet) {
            if ($Type -eq "Registry") {
                try {
                    if ($PSBoundParameters.ContainsKey('Credential')) {
                        Invoke-Command -ComputerName $Computer -Credential $Credential {
                            $Wow64 = Get-ChildItem "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\"                           
                            Foreach ($W in $Wow64) {
                                $Item = Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$($W.PSChildName)\"                              
                                if ($null -ne $item.installdate) {
                                    $Year = $item.installdate.substring(0, 4)
                                    $month = $item.installdate.substring(4, 2)
                                    $Day = $item.installdate.substring(4, 2)
                                    $installDate = "$Day/$month/$year"
                                }
                                else { $installDate = "" }

                                [pscustomobject]@{
                                    ComputerName    = $Env:COMPUTERNAME
                                    Node            = "Wow6432Node"
                                    Name            = $Item.DisplayName
                                    Publisher       = $Item.Publisher
                                    Version         = $Item.DisplayVersion
                                    InstallLocation = $Item.InstallLocation
                                    InstallDate     = $installdate
                                    EstimatedSize   = $Item.EstimatedSize
                                    URLInfoAbout    = $Item.URLInfoAbout
                                    ChildName       = $Item.PSChildName
                                }
                            }
                            $Standard = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\"
                            Foreach ($S in $Standard) {
                                $Item = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$($S.PSChildName)\"                              
                                if ($null -ne $item.installdate) {
                                    $Year = $item.installdate.substring(0, 4)
                                    $month = $item.installdate.substring(4, 2)
                                    $Day = $item.installdate.substring(4, 2)
                                    $installDate = "$Day/$month/$year"
                                }
                                else { $installDate = "" }

                                [pscustomobject]@{
                                    ComputerName    = $Env:COMPUTERNAME
                                    Node            = "Standard"
                                    Name            = $Item.DisplayName
                                    Publisher       = $Item.Publisher
                                    Version         = $Item.DisplayVersion
                                    InstallLocation = $Item.InstallLocation
                                    InstallDate     = $installdate
                                    EstimatedSize   = $Item.EstimatedSize
                                    URLInfoAbout    = $Item.URLInfoAbout
                                    ChildName       = $Item.PSChildName
                                }
                            }
                        }
                    }
                    else {
                        Invoke-Command -ComputerName $Computer {
                            $Wow64 = Get-ChildItem "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\"                           
                            Foreach ($W in $Wow64) {
                                $Item = Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$($W.PSChildName)\"                              
                                if ($null -ne $item.installdate) {
                                    $Year = $item.installdate.substring(0, 4)
                                    $month = $item.installdate.substring(4, 2)
                                    $Day = $item.installdate.substring(4, 2)
                                    $installDate = "$Day/$month/$year"
                                }
                                else { $installDate = "" }

                                [pscustomobject]@{
                                    ComputerName    = $Env:COMPUTERNAME
                                    Node            = "Wow6432Node"
                                    Name            = $Item.DisplayName
                                    Publisher       = $Item.Publisher
                                    Version         = $Item.DisplayVersion
                                    InstallLocation = $Item.InstallLocation
                                    InstallDate     = $installdate
                                    EstimatedSize   = $Item.EstimatedSize
                                    URLInfoAbout    = $Item.URLInfoAbout
                                    ChildName       = $Item.PSChildName
                                }
                            }
                            $Standard = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\"
                            Foreach ($S in $Standard) {
                                $Item = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$($S.PSChildName)\"                              
                                if ($null -ne $item.installdate) {
                                    $Year = $item.installdate.substring(0, 4)
                                    $month = $item.installdate.substring(4, 2)
                                    $Day = $item.installdate.substring(4, 2)
                                    $installDate = "$Day/$month/$year"
                                }
                                else { $installDate = "" }

                                [pscustomobject]@{
                                    ComputerName    = $Env:COMPUTERNAME
                                    Node            = "Standard"
                                    Name            = $Item.DisplayName
                                    Publisher       = $Item.Publisher
                                    Version         = $Item.DisplayVersion
                                    InstallLocation = $Item.InstallLocation
                                    InstallDate     = $installdate
                                    EstimatedSize   = $Item.EstimatedSize
                                    URLInfoAbout    = $Item.URLInfoAbout
                                    ChildName       = $Item.PSChildName
                                }
                            }
                        }
                    }
                }
                catch {
                    Write-Warning "Unable to capture Data from $Computer."
                }
            }
            else {
                try {
                    if ($PSBoundParameters.ContainsKey('Credential')) {
                        $CIMSession = New-CimSession -ComputerName $Computer -Credential $Credential
                        Get-CimInstance -Class win32_product -CimSession $CIMSession | Select-Object PSComputerName, Name, Vendor, Version
                        Remove-CimSession $CIMSession
                    }
                    else {
                        Get-CimInstance -ClassName win32_product -ComputerName $Computer | Select-Object PSComputerName, Name, Vendor, Version
                    }
                }
                catch {
                    try {
                        if ($PSBoundParameters.ContainsKey('Credential')) {
                            Get-WmiObject -Class win32_product -ComputerName $Computer -Credential $Credential | Select-Object PSComputerName, Name, Vendor, Version
                        }
                        else {
                            Get-WmiObject -Class win32_product -ComputerName $Computer | Select-Object PSComputerName, Name, Vendor, Version
                        }
                    }
                    catch {
                        Write-Warning "Unable to capture Data from $Computer."
                    }
                }
            } 
        }
        else {
            Write-Warning "$Computer is offline."
        }
    }
} #Review - Testing, Documentation
function Get-SHDComputerSoundDevices {   
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
                    Get-CimInstance -ClassName win32_sounddevice -CimSession $CIMSession | Select-Object PSComputerName, Manufacturer, Name, DeviceID, Status
                    Remove-CimSession $CIMSession
                }
                else {
                    Get-CimInstance -ClassName win32_sounddevice -ComputerName $Computer | Select-Object PSComputerName, Manufacturer, Name, DeviceID, Status
                }
            }
            catch {
                try {
                    if ($PSBoundParameters.ContainsKey('Credential')) {
                        Get-WmiObject -Class win32_sounddevice -ComputerName $Computer -Credential $Credential | Select-Object PSComputerName, Manufacturer, Name, DeviceID, Status
                    }
                    else {
                        Get-WmiObject -Class win32_sounddevice -ComputerName $Computer | Select-Object PSComputerName, Manufacturer, Name, DeviceID, Status
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
function Get-SHDComputerStartupCommands {
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
                    Get-CimInstance -ClassName win32_startupcommand -CimSession $CIMSession | Select-Object PSComputerName, Name, Command, Location, user 
                    Remove-CimSession $CIMSession
                }
                else {
                    Get-CimInstance -ClassName win32_startupcommand -ComputerName $Computer | Select-Object PSComputerName, Name, Command, Location, user 
                }
            }
            catch {
                try {
                    if ($PSBoundParameters.ContainsKey('Credential')) {
                        Get-WmiObject -Class win32_startupcommand -ComputerName $Computer -Credential $Credential | Select-Object PSComputerName, Name, Command, Location, user 
                    }
                    else {
                        Get-WmiObject -Class win32_startupcommand -ComputerName $Computer | Select-Object PSComputerName, Name, Command, Location, user 
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
function Get-SHDComputerStats {
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
                    $Processors = Get-CimInstance -ClassName win32_Processor -CimSession $cimsession | Sort-Object DeviceID | Select-Object -Property @(
                        @{l = "Name"; e = { $_.name } }
                        @{l = "Cores"; e = { $_.Numberofcores } }
                        @{l = "LogicalCores"; e = { $_.Numberoflogicalprocessors } }
                        @{l = "Level"; e = { $_.level } }
                    )
                    $RamChips = Get-CimInstance -ClassName win32_PhysicalMemory -CimSession $cimsession | Sort-Object BankLabel | Select-Object -Property @(
                        @{l = "Bank"; e = { $_.banklabel.split(' ')[1] } }
                        @{l = "Size/gb"; e = { $_.Capacity/1gb } }
                        @{l = "speed"; e = { $_.speed } }
                    )
            
                    $Disks = Get-CimInstance -ClassName win32_DiskDrive -CimSession $cimsession | Sort-Object DeviceID | Select-Object -Property @(
                        @{l = "ID"; e = { $_.DeviceID.split('\')[-1] } }
                        @{l = "Size/gb"; e = { [math]::Round($_.size/1gb) } }
                    )
                    $Monitors = Get-CimInstance -ClassName win32_DesktopMonitor -CimSession $cimsession | Sort-Object deviceID | Select-Object -Property @(
                        @{l = "Name"; e = { $_.Name } }
                        @{l = "Height"; e = { $_.ScreenHeight } }
                        @{l = "Width"; e = { $_.ScreenWidth } }
                    )
                    $GPUs = Get-CimInstance -ClassName win32_VideoController -CimSession $cimsession | Sort-Object deviceid | Select-Object -Property @(
                        @{l = "Name"; e = { $_.name } }
                        @{l = "Ram/gb"; e = { [math]::Round($_.AdapterRAM/1gb) } }
                        @{l = "Processor"; e = { $_.VideoProcessor } }
                        @{l = "Colors"; e = { $_.CurrentNumberOfColors } }
                        @{l = "Resolution"; e = { "$($_.CurrentHorizontalResolution)/$($_.CurrentVerticalResolution)" } }
                        @{l = "MaxRefresh"; e = { $_.MaxRefreshRate } }
                    )
                    $OS = Get-CimInstance -ClassName win32_OperatingSystem -CimSession $cimsession | Select-Object -Property @(
                        @{l = "OS"; e = { "$($_.caption) $($_.OSArchitecture) ($($_.BuildNumber))" } }
                    )
                    [pscustomobject]@{
                        ComputerName = $Computer
                        OS           = $OS.OS
                        Processors   = $Processors.name
                        Ram          = ($RamChips."Size/gb" | Measure-Object -Sum).Sum
                        Disk         = ($Disks."Size/gb" | Measure-Object -Sum).Sum
                        Monitors     = $Monitors.Count
                        GPU          = $GPUs.name
                    }
                    Remove-CimSession $CIMSession
                }
                else {
                    $Processors = Get-CimInstance -ClassName win32_Processor -ComputerName $Computer | Sort-Object DeviceID | Select-Object -Property @(
                        @{l = "Name"; e = { $_.name } }
                        @{l = "Cores"; e = { $_.Numberofcores } }
                        @{l = "LogicalCores"; e = { $_.Numberoflogicalprocessors } }
                        @{l = "Level"; e = { $_.level } }
                    )
                    $RamChips = Get-CimInstance -ClassName win32_PhysicalMemory -ComputerName $Computer | Sort-Object BankLabel | Select-Object -Property @(
                        @{l = "Bank"; e = { $_.banklabel.split(' ')[1] } }
                        @{l = "Size/gb"; e = { $_.Capacity/1gb } }
                        @{l = "speed"; e = { $_.speed } }
                    )
            
                    $Disks = Get-CimInstance -ClassName win32_DiskDrive -ComputerName $Computer | Sort-Object DeviceID | Select-Object -Property @(
                        @{l = "ID"; e = { $_.DeviceID.split('\')[-1] } }
                        @{l = "Size/gb"; e = { [math]::Round($_.size/1gb) } }
                    )
                    $Monitors = Get-CimInstance -ClassName win32_DesktopMonitor -ComputerName $Computer | Sort-Object deviceID | Select-Object -Property @(
                        @{l = "Name"; e = { $_.Name } }
                        @{l = "Height"; e = { $_.ScreenHeight } }
                        @{l = "Width"; e = { $_.ScreenWidth } }
                    )
                    $GPUs = Get-CimInstance -ClassName win32_VideoController -ComputerName $Computer | Sort-Object deviceid | Select-Object -Property @(
                        @{l = "Name"; e = { $_.name } }
                        @{l = "Ram/gb"; e = { [math]::Round($_.AdapterRAM/1gb) } }
                        @{l = "Processor"; e = { $_.VideoProcessor } }
                        @{l = "Colors"; e = { $_.CurrentNumberOfColors } }
                        @{l = "Resolution"; e = { "$($_.CurrentHorizontalResolution)/$($_.CurrentVerticalResolution)" } }
                        @{l = "MaxRefresh"; e = { $_.MaxRefreshRate } }
                    )
                    $OS = Get-CimInstance -ClassName win32_OperatingSystem -ComputerName $Computer | Select-Object -Property @(
                        @{l = "OS"; e = { "$($_.caption) $($_.OSArchitecture) ($($_.BuildNumber))" } }
                    )
                    [pscustomobject]@{
                        ComputerName = $Computer
                        OS           = $OS.OS
                        Processors   = $Processors.name
                        Ram          = ($RamChips."Size/gb" | Measure-Object -Sum).Sum
                        Disk         = ($Disks."Size/gb" | Measure-Object -Sum).Sum
                        Monitors     = $Monitors.Count
                        GPU          = $GPUs.name
                    }
                }
            }
            catch {
                try {
                    if ($PSBoundParameters.ContainsKey('Credential')) {
                        $Processors = Get-WmiObject -Class win32_Processor -ComputerName $Computer -Credential $Credential | Sort-Object DeviceID | Select-Object -Property @(
                            @{l = "Name"; e = { $_.name } }
                            @{l = "Cores"; e = { $_.Numberofcores } }
                            @{l = "LogicalCores"; e = { $_.Numberoflogicalprocessors } }
                            @{l = "Level"; e = { $_.level } }
                        )
                        $RamChips = Get-WmiObject -Class win32_PhysicalMemory -ComputerName $Computer -Credential $Credential | Sort-Object BankLabel | Select-Object -Property @(
                            @{l = "Bank"; e = { $_.banklabel.split(' ')[1] } }
                            @{l = "Size/gb"; e = { $_.Capacity/1gb } }
                            @{l = "speed"; e = { $_.speed } }
                        )
                
                        $Disks = Get-WmiObject -Class win32_DiskDrive -ComputerName $Computer -Credential $Credential | Sort-Object DeviceID | Select-Object -Property @(
                            @{l = "ID"; e = { $_.DeviceID.split('\')[-1] } }
                            @{l = "Size/gb"; e = { [math]::Round($_.size/1gb) } }
                        )
                        $Monitors = Get-WmiObject -Class win32_DesktopMonitor -ComputerName $Computer -Credential $Credential | Sort-Object deviceID | Select-Object -Property @(
                            @{l = "Name"; e = { $_.Name } }
                            @{l = "Height"; e = { $_.ScreenHeight } }
                            @{l = "Width"; e = { $_.ScreenWidth } }
                        )
                        $GPUs = Get-WmiObject -Class win32_VideoController -ComputerName $Computer -Credential $Credential | Sort-Object deviceid | Select-Object -Property @(
                            @{l = "Name"; e = { $_.name } }
                            @{l = "Ram/gb"; e = { [math]::Round($_.AdapterRAM/1gb) } }
                            @{l = "Processor"; e = { $_.VideoProcessor } }
                            @{l = "Colors"; e = { $_.CurrentNumberOfColors } }
                            @{l = "Resolution"; e = { "$($_.CurrentHorizontalResolution)/$($_.CurrentVerticalResolution)" } }
                            @{l = "MaxRefresh"; e = { $_.MaxRefreshRate } }
                        )
                        $OS = Get-WmiObject -Class win32_OperatingSystem -ComputerName $Computer -Credential $Credential | Select-Object -Property @(
                            @{l = "OS"; e = { "$($_.caption) $($_.OSArchitecture) ($($_.BuildNumber))" } }
                        )
                        [pscustomobject]@{
                            ComputerName = $Computer
                            OS           = $OS.OS
                            Processors   = $Processors.name
                            Ram          = ($RamChips."Size/gb" | Measure-Object -Sum).Sum
                            Disk         = ($Disks."Size/gb" | Measure-Object -Sum).Sum
                            Monitors     = $Monitors.Count
                            GPU          = $GPUs.name
                        }
                    }
                    else {
                        $Processors = Get-WmiObject -Class win32_Processor -ComputerName $Computer | Sort-Object DeviceID | Select-Object -Property @(
                            @{l = "Name"; e = { $_.name } }
                            @{l = "Cores"; e = { $_.Numberofcores } }
                            @{l = "LogicalCores"; e = { $_.Numberoflogicalprocessors } }
                            @{l = "Level"; e = { $_.level } }
                        )
                        $RamChips = Get-WmiObject -Class win32_PhysicalMemory -ComputerName $Computer | Sort-Object BankLabel | Select-Object -Property @(
                            @{l = "Bank"; e = { $_.banklabel.split(' ')[1] } }
                            @{l = "Size/gb"; e = { $_.Capacity/1gb } }
                            @{l = "speed"; e = { $_.speed } }
                        )
                
                        $Disks = Get-WmiObject -Class win32_DiskDrive -ComputerName $Computer | Sort-Object DeviceID | Select-Object -Property @(
                            @{l = "ID"; e = { $_.DeviceID.split('\')[-1] } }
                            @{l = "Size/gb"; e = { [math]::Round($_.size/1gb) } }
                        )
                        $Monitors = Get-WmiObject -Class win32_DesktopMonitor -ComputerName $Computer | Sort-Object deviceID | Select-Object -Property @(
                            @{l = "Name"; e = { $_.Name } }
                            @{l = "Height"; e = { $_.ScreenHeight } }
                            @{l = "Width"; e = { $_.ScreenWidth } }
                        )
                        $GPUs = Get-WmiObject -Class win32_VideoController -ComputerName $Computer | Sort-Object deviceid | Select-Object -Property @(
                            @{l = "Name"; e = { $_.name } }
                            @{l = "Ram/gb"; e = { [math]::Round($_.AdapterRAM/1gb) } }
                            @{l = "Processor"; e = { $_.VideoProcessor } }
                            @{l = "Colors"; e = { $_.CurrentNumberOfColors } }
                            @{l = "Resolution"; e = { "$($_.CurrentHorizontalResolution)/$($_.CurrentVerticalResolution)" } }
                            @{l = "MaxRefresh"; e = { $_.MaxRefreshRate } }
                        )
                        $OS = Get-WmiObject -Class win32_OperatingSystem -ComputerName $Computer | Select-Object -Property @(
                            @{l = "OS"; e = { "$($_.caption) $($_.OSArchitecture) ($($_.BuildNumber))" } }
                        )
                        [pscustomobject]@{
                            ComputerName = $Computer
                            OS           = $OS.OS
                            Processors   = $Processors.name
                            Ram          = ($RamChips."Size/gb" | Measure-Object -Sum).Sum
                            Disk         = ($Disks."Size/gb" | Measure-Object -Sum).Sum
                            Monitors     = $Monitors.Count
                            GPU          = $GPUs.name
                        }
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
function Get-SHDComputerSystemTime {
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
                    Get-CimInstance -ClassName Win32_OperatingSystem -CimSession $cimsession | Select-Object PSComputerName, LocalDateTime
                    Remove-CimSession $CIMSession
                }
                else {
                    Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $computer | Select-Object PSComputerName, LocalDateTime
                }
            }
            catch {
                try {
                    if ($PSBoundParameters.ContainsKey('Credential')) {
                        $ComputerOS = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName -Credential $Credential
                        $ComputerOS | Add-Member ScriptProperty -Name DateTime -Value { $this.converttodatetime($ComputerOS.LocalDateTime) }
                        [pscustomobject]@{
                            ComputerName = $ComputerName 
                            SystemTime   = $ComputerOS.Datetime
                        }
                    }
                    else {
                        $ComputerOS = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName
                        $ComputerOS | Add-Member ScriptProperty -Name DateTime -Value { $this.converttodatetime($ComputerOS.LocalDateTime) }
                        [pscustomobject]@{
                            ComputerName = $ComputerName 
                            SystemTime   = $ComputerOS.Datetime
                        }
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
function Get-SHDComputerTPMChip {
    <#
    .SYNOPSIS
    .DESCRIPTION
    .PARAMETER
    .EXAMPLE
    .INPUTS
    .OUTPUTS
    .NOTES
    .LINK
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
                    Get-CimInstance -ClassName win32_tpm -CimSession $CIMSession -Namespace "root\cimv2\Security\MicrosoftTPM"
                    Remove-CimSession $CIMSession
                }
                else {
                    Get-CimInstance -ClassName win32_tpm -ComputerName $Computer -Namespace "root\cimv2\Security\MicrosoftTPM"
                }
            }
            catch {
                try {
                    if ($PSBoundParameters.ContainsKey('Credential')) {
                        Get-WmiObject -Class win32_tpm -ComputerName $Computer -Namespace "root\cimv2\Security\MicrosoftTPM" -credential $Credential
                    }
                    else {
                        Get-WmiObject -Class win32_tpm -ComputerName $Computer -Namespace "root\cimv2\Security\MicrosoftTPM"
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

} #Review - Testing,Documentation
function Get-SHDComputerUptime {
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
                    $CIMSession = New-CimSession -ComputerName $computer -Credential $Credential
                    $ComputerOS = Get-CimInstance -Class Win32_OperatingSystem -CimSession $CIMSession
                    $ComputerOS | Add-Member ScriptProperty -name Uptime -Value { $ComputerOS.LocalDateTime - $computerOS.LastBootUpTime }
                    [pscustomobject][ordered]@{
                        ComputerName = $Computer
                        Uptime       = $ComputerOS.Uptime.ToString()
                    }
                    Remove-CimSession $CIMSession
                }
                else {
                    $ComputerOS = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $Computer
                    $ComputerOS | Add-Member ScriptProperty -name Uptime -Value { $ComputerOS.LocalDateTime - $computerOS.LastBootUpTime }
                    [pscustomobject][ordered]@{
                        ComputerName = $Computer
                        Uptime       = $ComputerOS.Uptime.ToString()
                    }
                }
            }
            catch {
                try {
                    if ($PSBoundParameters.ContainsKey('Credential')) {
                        $ComputerOS = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Computer -Credential $Credential
                        $ComputerOS | Add-Member ScriptProperty -Name DateTime -Value { $this.converttodatetime($ComputerOS.LocalDateTime) }
                        $ComputerOS | Add-Member ScriptProperty -Name InstallDateTime -Value { $this.converttodatetime($ComputerOS.InstallDate) }
                        $ComputerOS | Add-Member ScriptProperty -name LastBootDateTime -Value { [System.Management.ManagementDateTimeConverter]::ToDateTime($ComputerOS.lastbootuptime) }
                        $ComputerOS | Add-Member ScriptProperty -name Uptime -Value { $ComputerOS.Datetime - $computerOS.LastBootDateTime }
                        [pscustomobject][ordered]@{
                            ComputerName = $Computer
                            Uptime       = $ComputerOS.Uptime.ToString()
                        }
                    }
                    else {
                        $ComputerOS = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Computer
                        $ComputerOS | Add-Member ScriptProperty -Name DateTime -Value { $this.converttodatetime($ComputerOS.LocalDateTime) }
                        $ComputerOS | Add-Member ScriptProperty -Name InstallDateTime -Value { $this.converttodatetime($ComputerOS.InstallDate) }
                        $ComputerOS | Add-Member ScriptProperty -name LastBootDateTime -Value { [System.Management.ManagementDateTimeConverter]::ToDateTime($ComputerOS.lastbootuptime) }
                        $ComputerOS | Add-Member ScriptProperty -name Uptime -Value { $ComputerOS.Datetime - $computerOS.LastBootDateTime }
                        [pscustomobject][ordered]@{
                            ComputerName = $Computer
                            Uptime       = $ComputerOS.Uptime.ToString()
                        }
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
function Get-SHDComputerUSB {
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
                    Get-PnpDevice -Class "USB" -CimSession $Cimsession | Select-Object SystemName, Status, Present, Service, Caption, Problem, InstanceID
                    Remove-CimSession $CIMSession
                }
                else {
                    Invoke-Command -ComputerName $Computer -ScriptBlock {
                        Get-PnpDevice -Class "USB" | Select-Object SystemName, Status, Present, Service, Caption, Problem, InstanceID
                    }
                }
            }
            catch {
                Write-Warning "Unable to capture Data from $Computer."
            }
        }
        else {
            Write-Warning "$Computer is offline."
        }
    }
} #Review - Testing, Documentation
function Get-SHDComputerVideoController {
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
                    $VideoControllers = Get-CimInstance -Class win32_videocontroller -CimSession $CIMSession
                    Foreach ($VideoController in $VideoControllers) {
                        [pscustomobject]@{
                            ComputerName    = $Computer
                            name            = $VideoController.name
                            "DriverVersion" = $VideoController.DriverVersion
                            AdapterType     = $VideoController.adapterDACType
                            AdapterRam      = $VideoController.adapterram
                            MemoryType      = $VideoController.VideoMemoryType
                            MaxRefreshRate  = $VideoController.maxrefreshrate
                        }
                    }
                    Remove-CimSession $CIMSession
                }
                else {
                    $VideoControllers = Get-CimInstance -Class win32_videocontroller -ComputerName $Computer 
                    Foreach ($VideoController in $VideoControllers) {
                        [pscustomobject]@{
                            ComputerName    = $Computer
                            name            = $VideoController.name
                            "DriverVersion" = $VideoController.DriverVersion
                            AdapterType     = $VideoController.adapterDACType
                            AdapterRam      = $VideoController.adapterram
                            MemoryType      = $VideoController.VideoMemoryType
                            MaxRefreshRate  = $VideoController.maxrefreshrate
                        }
                    }
                }
            }
            catch {
                try {
                    if ($PSBoundParameters.ContainsKey('Credential')) {
                        $VideoControllers = Get-WmiObject -Class win32_videocontroller -ComputerName $Computer -Credential $Credential
                        Foreach ($VideoController in $VideoControllers) {
                            [pscustomobject]@{
                                ComputerName    = $Computer
                                name            = $VideoController.name
                                "DriverVersion" = $VideoController.DriverVersion
                                AdapterType     = $VideoController.adapterDACType
                                AdapterRam      = $VideoController.adapterram
                                MemoryType      = $VideoController.VideoMemoryType
                                MaxRefreshRate  = $VideoController.maxrefreshrate
                            }
                        }
                    }
                    else {
                        $VideoControllers = Get-WmiObject -Class win32_videocontroller -ComputerName $Computer 
                        Foreach ($VideoController in $VideoControllers) {
                            [pscustomobject]@{
                                ComputerName    = $Computer
                                name            = $VideoController.name
                                "DriverVersion" = $VideoController.DriverVersion
                                AdapterType     = $VideoController.adapterDACType
                                AdapterRam      = $VideoController.adapterram
                                MemoryType      = $VideoController.VideoMemoryType
                                MaxRefreshRate  = $VideoController.maxrefreshrate
                            }
                        }
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
function Get-SHDComputerWindowsActivationStatus {
    [cmdletbinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Provide the target hostname",
            Mandatory = $true)][Alias('Hostname', 'cn')][String[]]$Computername,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )
    $lstat = DATA {
        ConvertFrom-StringData -StringData @’
0 = "Unlicensed"
1 = "Licensed"
2 = "OOB Grace"
3 = "OOT Grace"
4 = "Non-Genuine Grace"
5 = "Notification"
6 = "Extended Grace"
‘@
    }
    foreach ($computer in $Computername) {
        if (Test-Connection -ComputerName $computer -Count 1 -Quiet) {
            try {
                if ($PSBoundParameters.ContainsKey('Credential')) {
                    $CIMSession = New-CimSession -ComputerName $Computer -Credential $Credential
                    Get-CimInstance SoftwareLicensingProduct -Filter "Name like 'Windows%'" -CimSession $cimsession | Where-Object { $_.PartialProductKey } | Select-Object PSComputerNameDescription, @{N = ”LicenseStatus”; E = { $lstat[“$($_.LicenseStatus)”] } }, LicenseFamily, LicenseStatusReason
                    Remove-CimSession $CIMSession
                }
                else {
                    Get-CimInstance SoftwareLicensingProduct -Filter "Name like 'Windows%'" -ComputerName $computer | Where-Object { $_.PartialProductKey } | Select-Object PSComputerName, Description, @{N = ”LicenseStatus”; E = { $lstat[“$($_.LicenseStatus)”] } }, LicenseFamily, LicenseStatusReason
                }
            }
            catch {
                try {
                    if ($PSBoundParameters.ContainsKey('Credential')) {
                        get-wmiobject SoftwareLicensingProduct -Filter "Name like 'Windows%'" -Credential $Credential -ComputerName $computer | Where-Object { $_.PartialProductKey } | Select-Object PSComputerName, Description, @{N = ”LicenseStatus”; E = { $lstat[“$($_.LicenseStatus)”] } }, LicenseFamily, LicenseStatusReason
                    }
                    else {
                        get-wmiobject SoftwareLicensingProduct -Filter "Name like 'Windows%'" -ComputerName $computer | Where-Object { $_.PartialProductKey } | Select-Object PSComputerName, Description, @{N = ”LicenseStatus”; E = { $lstat[“$($_.LicenseStatus)”] } }, LicenseFamily, LicenseStatusReason
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
function Get-SHDComputerWindowsStats {
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
                    Get-CimInstance -ClassName win32_winsat -CimSession $CIMSession
                    Remove-CimSession $CIMSession
                }
                else {
                    Get-CimInstance -ClassName win32_winsat -ComputerName $Computer
                }
            }
            catch {
                try {
                    if ($PSBoundParameters.ContainsKey('Credential')) {
                        Get-WmiObject -Class win32_winsat -ComputerName $Computer -Credential $Credential
                    }
                    else {
                        Get-WmiObject -Class win32_winsat -ComputerName $Computer
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
function Get-SHDComputerWireless {
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
                    Get-CimInstance -ClassName win32_networkadapter -CimSession $CIMSession | Where-Object { $_.name -like "*Wireless*" } | Select-Object pscomputername, name, macaddress, speed
                    Remove-CimSession $CIMSession
                }
                else {
                    Get-CimInstance -ClassName win32_networkadapter -ComputerName $Computer | Where-Object { $_.name -like "*Wireless*" } | Select-Object pscomputername, name, macaddress, speed
                }
            }
            catch {
                try {
                    if ($PSBoundParameters.ContainsKey('Credential')) {
                        get-wmiobject -Class win32_networkadapter -ComputerName $Computer -Credential $Credential | Where-Object { $_.name -like "*Wireless*" } | Select-Object pscomputername, name, macaddress, speed
                    }
                    else {
                        get-wmiobject -Class win32_networkadapter -ComputerName $Computer | Where-Object { $_.name -like "*Wireless*" } | Select-Object pscomputername, name, macaddress, speed
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
function Get-SHDComputerWSUSUpdates {
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
        if (Test-Connection -ComputerName $Computer -Quiet -Count 1) {
            if ($PSBoundParameters.ContainsKey('Credential')) {
                Invoke-Command -ComputerName $Computer -Credential $Credential -ScriptBlock {
                    #Get-Item HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate
                    $Servername = (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name WUServer).wuserver
                    $Elevation = (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name ElevateNonAdmins).ElevateNonAdmins
                    $TargetGroup = (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name TargetGroup).TargetGroup
                    $UseWSUerver = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'UseWUServer').UseWUServer
                    $Return = [pscustomobject][ordered]@{
                        ComputerName      = $args[0]
                        Servername        = $Servername
                        RequiresElevation = $Elevation
                        TargetGroup       = $TargetGroup
                        UseWSUSServer     = $UseWSUerver
                    }
                    $Return 
                } -ArgumentList $Computer
            }
            else {
                Invoke-Command -ComputerName $Computer -ScriptBlock {
                    #Get-Item HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate
                    $Servername = (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name WUServer).wuserver
                    $Elevation = (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name ElevateNonAdmins).ElevateNonAdmins
                    $TargetGroup = (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name TargetGroup).TargetGroup
                    $UseWSUerver = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'UseWUServer').UseWUServer
                    $Return = [pscustomobject][ordered]@{
                        ComputerName      = $args[0]
                        Servername        = $Servername
                        RequiresElevation = $Elevation
                        TargetGroup       = $TargetGroup
                        UseWSUSServer     = $UseWSUerver
                    }
                    $Return
                } -ArgumentList $Computer
            }
        }
        else {
            Write-Warning "$Comptuer Offline"
        }
    }
} #Review - Test, Documentation

#-------------------------Computer - Get -----------------------------------#
#-------------------------Computer - Remove --------------------------------#
function Remove-SHDComputerLocalGroupMember {
    <#
    .SYNOPSIS
        Removes username to target group on target computer. 
    .DESCRIPTION
        Loops through a list of computers and removes a list of users inside a of computers on each computer. 
    .PARAMETER Computername
        [String[]] - List of target computers to search the groups and added users with. 
    .PARAMETER GroupName
        [String[]] - List of Groups to add users to.
    .PARAMETER Username
        [String[]] - List of Usernames to add to groups on target computer
    .PARAMETER Credential
        Optional credentials switch that allows you to use another credential.
    .EXAMPLE
        Remove-SHDComputerLocalGroupMember -ComputerName <Server1>,<Server2>,<Server3> -GroupName "Remote Desktop Users","Users" -Username "User1","User2","User3"

        Remove User1, User2, and User3 to the remote desktop user group and the users group on server1, server2, server3 using the currently running credentials.
    .EXAMPLE
        Remove-SHDComputerLocalGroupMember -ComputerName <Server1>,<Server2>,<Server3> -GroupName "Remote Desktop Users","Users" -Username "User1","User2","User3" -Credential (Get-Credential)

        Remove User1, User2, and User3 to the remote desktop user group and the users group on server1, server2, server3 using the credentials provided.
    .INPUTS
        Array of ComputerNames
    .OUTPUTS
        System.Object
    .NOTES

    .LINK
        https://www.bolding.us
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
    foreach ($computer in $Computername) {
        if (Test-Connection -ComputerName $computer -Count 1 -Quiet) {
            foreach ($Group in $GroupName) {
                Foreach ($User in $username) {
                    try {
                        if ($PSBoundParameters.ContainsKey('Credential')) {
                            Invoke-Command -ComputerName $computer -Credential $Credential -ScriptBlock {
                                Remove-LocalGroupMember -Group $args[0] -Member $args[1] -Confirm:$false
                                Get-LocalGroupMember -Group $args[0]
                            } -ArgumentList $Group, $User | Select-Object PScomputername, ObjectClass, name, principalsource
                        }
                        else {
                            Invoke-Command -ComputerName $computer -ScriptBlock {
                                Remove-LocalGroupMember -Group $args[0] -Member $args[1] -Confirm:$false
                                Get-LocalGroupMember -Group $args[0]
                            } -ArgumentList $Group, $User | Select-Object PScomputername, ObjectClass, name, principalsource
                        }
                    }
                    catch {
                        Write-Warning "Unable to access $computer information."
                    }
                }
            }
        }
        else {
            Write-Warning "$Computer offline."
        }
    }
} #Review - testing, Documentation

function Remove-SHDComputerLocalGroup {
    [cmdletbinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Provide the target hostname",
            Mandatory = $true)][Alias('Hostname', 'cn')][String[]]$Computername,
        [Parameter(HelpMessage = "Target Group", Mandatory = $True)][String]$Name,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )
    foreach ($computer in $Computername) {
        if (Test-Connection -ComputerName $computer -Count 1 -Quiet) {
            if ($PSBoundParameters.ContainsKey('Credential')) {
                invoke-command -ComputerName $computer -Credential $Credential -ScriptBlock {
                    try { $Temp = Get-LocalGroup -Name $args[0] }
                    catch { $Temp = $null }
                    if ($null -eq $Temp) {
                        Remove-LocalGroup -Name $args[0] -Confirm:$false 
                        Get-LocalGroup -Name $args[0]
                    }
                } -ArgumentList $name, $Description
            }
            else {
                invoke-command -ComputerName $computer -ScriptBlock {
                    try { $Temp = Get-LocalGroup -Name $args[0] }
                    catch { $Temp = $null }
                    if ($null -eq $Temp) {
                        Remove-LocalGroup -Name $args[0] -Confirm:$false 
                        Get-LocalGroup -Name $args[0]
                    }
                } -ArgumentList $name, $Description
            }
        }
        else {
            Write-Warning "$Computer offline."
        }
    }

} #Review - Testing, Documentation
function Remove-SHDComputerProfile {
    [cmdletbinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Provide the target hostname",
            Mandatory = $true)][Alias('Hostname', 'cn')][String[]]$Computername,
        [Parameter(HelpMessage = "Usernames", Mandatory = $True)][alias('User', 'Samaccountname')][string[]]$Username,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )
    foreach ($computer in $Computername) {
        if (Test-Connection -ComputerName $computer -Count 1 -Quiet) {
            Foreach ($user in $username) {
                if ($PSBoundParameters.ContainsKey('Credential')) {
                    $CIMInstance = New-CimSession -ComputerName $computer -Credential $Credential
                    #win32_userprofile
                    $UserProfiles = Get-CimInstance -ClassName win32_userprofile -CimSession $CIMInstance | Sort-Object LocalPath | Where-Object { $_.LocalPath -like "*$user*" } #| Select-Object @{Label = "ComputerName"; Expression = { $computer } }, @{Label = "Username"; Expression = { $_.LocalPath -replace '.*\\', '' } }, LocalPath, Special, Loaded
                    foreach ($Pro in $UserProfiles) {
                        $Pro | Remove-CimInstance -Confirm:$false
                    }
                    Get-CimInstance -ClassName win32_userprofile -CimSession $CIMInstance | Sort-Object LocalPath | Select-Object @{Label = "ComputerName"; Expression = { $computer } }, @{Label = "Username"; Expression = { $_.LocalPath -replace '.*\\', '' } }, LocalPath, Special, Loaded
                    Remove-CimSession $CIMInstance
                }
                else {
                    $UserProfiles = Get-CimInstance -ClassName win32_userprofile -ComputerName $Computer | Where-Object { $_.LocalPath -like "*$user*" } | Sort-Object LocalPath #| Select-Object @{Label = "ComputerName"; Expression = { $computer } }, @{Label = "Username"; Expression = { $_.LocalPath -replace '.*\\', '' } }, LocalPath, Special, Loaded
                    foreach ($Pro in $UserProfiles) {
                        $Pro | Remove-CimInstance -Confirm:$false
                    }
                    Get-CimInstance -ClassName win32_userprofile -ComputerName $computer | Sort-Object LocalPath | Select-Object @{Label = "ComputerName"; Expression = { $computer } }, @{Label = "Username"; Expression = { $_.LocalPath -replace '.*\\', '' } }, LocalPath, Special, Loaded
                }
            }
        }
        else {
            Write-Warning "$Computer is offline."
        }
    }
} #Review - Testing, Documentation
function Remove-SHDComputerAllDomainProfiles {
    <#
    .SYNOPSIS
    .DESCRIPTION
    .PARAMETER
    .EXAMPLE
    .INPUTS
    .OUTPUTS
    .NOTES
    .LINK
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
                    Invoke-Command -computername $computer -Credential $Credential -ScriptBlock {
                        $UserProfiles = Get-CimInstance -ClassName Win32_UserProfile | Where-Object { ($_.Special -ne $True) -and ($_.Loaded -ne $True) }
                        $LocalUsers = Get-LocalUser
                        foreach ($pro in $UserProfiles) {
                            $Username = $pro.localpath.split('\')[-1]
                            if ($LocalUsers.name -contains $Username) {
                                "Local Account: $Username" >> c:\tbc\AccountRemoval.log
                            }
                            else {
                                "Removing Domain Account: $Username" >> c:\tbc\AccountRemoval.log
                                $pro | Remove-CimInstance -Confirm:$false -Verbose
                            }
                        }
                    }
                }
                else {
                    Invoke-Command -computername $computer -ScriptBlock {
                        $UserProfiles = Get-CimInstance -ClassName Win32_UserProfile | Where-Object { ($_.Special -ne $True) -and ($_.Loaded -ne $True) }
                        $LocalUsers = Get-LocalUser
                        foreach ($pro in $UserProfiles) {
                            $Username = $pro.localpath.split('\')[-1]
                            if ($LocalUsers.name -contains $Username) {
                                "Local Account: $Username" >> c:\tbc\AccountRemoval.log
                            }
                            else {
                                "Removing Domain Account: $Username" >> c:\tbc\AccountRemoval.log
                                $pro | Remove-CimInstance -Confirm:$false -Verbose
                            }
                        }
                    }
                }
            }
            catch {
                Write-Warning "Unable to capture Data from $Computer."
            }
        }
        else {
            Write-Warning "$Computer is offline."
        }
        if ($PSBoundParameters.ContainsKey('Credential')) {
            Get-SHDComputerProfiles -Computername $computer -Credential $Credential
        }
        else {
            Get-SHDComputerProfiles -Computername $computer 
        }
    }
}
Function Remove-SHDComputerUserProfile {
    [cmdletbinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Provide the target hostname",
            Mandatory = $true)][Alias('Hostname', 'cn')][String[]]$Computername,
        [Parameter(HelpMessage = "Target Username", Mandatory = $True)]$Username,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )
    foreach ($computer in $Computername) {
        if (Test-Connection -ComputerName $computer -Count 1 -Quiet) {
            foreach ($user in $Username) {
                try {
                    if ($PSBoundParameters.ContainsKey('Credential')) {
                        $CIMSession = New-CimSession -ComputerName $Computer -Credential $Credential
                        Try {
                            $UserProfile = Get-CimInstance -ClassName Win32_UserProfile -Filter "localpath like 'c:\\Users\\%'" -CimSession $CIMSession | Where-Object { $_.LocalPath -like "*$user*" }
                            $UserProfile | Remove-CimInstance -Confirm:$false
                        }
                        catch {
                            Write-Warning "Unable To remove $user from $Computer With CimInstance and Credentials"
                        }
                        Remove-CimSession $CIMSession
                    }
                    else {
                        try {
                            $UserProfile = Get-CimInstance -ClassName Win32_UserProfile -Filter "localpath like 'c:\\Users\\%'" -ComputerName $computer | Where-Object { $_.LocalPath -like "*$user*" }
                            $UserProfile | Remove-CimInstance -Confirm:$false
                        }
                        catch {
                            Write-Warning "Unable To remove $user from $Computer with CimInstance"
                        }
                    }
                }
                catch {
                    try {
                        if ($PSBoundParameters.ContainsKey('Credential')) {
                            try {
                                $UserProfile = Get-WmiObject -ClassName Win32_UserProfile -Filter "localpath like 'c:\\Users\\%'" -ComputerName $computer -credential $Credential | Where-Object { $_.LocalPath -like "*$user*" }
                                $UserProfile | Remove-Wimobject -Confirm:$false
                            }
                            catch {
                                Write-Warning "Unable To remove $user from $Computer with WimObjects with Credential"
                            }
                        }
                        else {
                            Try {    
                                $UserProfile = Get-WmiObject -ClassName Win32_UserProfile -Filter "localpath like 'c:\\Users\\%'" -ComputerName $computer -credential $Credential | Where-Object { $_.LocalPath -like "*$user*" }
                                $UserProfile | Remove-Wimobject -Confirm:$false
                            }
                            catch {
                                Write-Warning "Unable To remove $user from $Computer with Wimobjects"
                            }
                        }
                    }
                    catch {
                        Write-Warning "Unable to capture Data from $Computer."
                    }
                }
            }
        }
        else {
            Write-Warning "$Computer is offline."
        }
    }
} #Review - Testing, Documentation

#-------------------------Computer - Remove --------------------------------#
#-------------------------Computer - Set -----------------------------------#
function Set-SHDMacAddressStructure {
    [cmdletbinding()]
    param (
        [parameter(Mandatory = $True)][ValidatePattern("^([0-9A-Fa-f]{2}[: \.-]){5}([0-9A-Fa-f]{2})$")][string]$MacAddress,
        [parameter(Mandatory = $true)][String]$Seperator,
        [Parameter(HelpMessage = "Changes the case")][Validateset("UpperCase", "LowerCase")]$Case,
        [parameter(helpmessage = "Added mac to clipboard")][switch]$ToClipboard
    )
    $Pattern = '[^a-zA-Z0-9]'
    $Mac = $MacAddress -replace $Pattern, $Seperator
    if ($case -eq "UpperCase") {
        if ($ToClipboard) {
            $Mac.ToUpper() | clip 
            $Mac.ToUpper()
        }
        else {
            $Mac.ToUpper()
        }
    }
    elseif ($case -eq "LowerCase") {
        if ($ToClipboard) {
            $Mac.ToLower() | clip 
            $Mac.ToLower()
        }
        else {
            $Mac.ToLower()
        }
    }
    else {
        if ($ToClipboard) {
            $Mac | clip 
            $Mac
        }
        else {
            $Mac
        }
    }
} #Review - Testing, Documentation
function Set-SHDComputerLocalUser {
    [cmdletbinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Provide the target hostname",
            Mandatory = $true)][Alias('Hostname', 'cn')][String[]]$Computername,
        [Parameter(HelpMessage = "DomainName/Username", Mandatory = $True)][string]$username,
        [Parameter(HelpMessage = "Local Name")][String]$name,
        [Parameter(HelpMessage = "Local Name")][String]$FullName,
        [Parameter(HelpMessage = "Local Name")][datetime]$Accountexpires,
        [Parameter(HelpMessage = "Local Name")][Switch]$AccountNeverExpires,
        [Parameter(HelpMessage = "Local Name")][String]$Description,
        [Parameter(HelpMessage = "Local Name")][securestring]$Password,
        [Parameter(HelpMessage = "Local Name")][Bool]$PasswordNeverExpires,
        [Parameter(HelpMessage = "Local Name")][Bool]$UserMayChangePassword,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )
    foreach ($computer in $Computername) {
        if (Test-Connection -ComputerName $computer -Count 1 -Quiet) {
            if ($PSBoundParameters.ContainsKey('Credential')) {
                if ($PSBoundParameters.ContainsKey('FullName')) {
                    invoke-command -ComputerName $computer -Credential $Credential -ScriptBlock {
                        Set-LocalUser -Name $args[0] -FullName $args[1] -Confirm:$false
                    } -ArgumentList $username, $FullName
                }
                if ($PSBoundParameters.ContainsKey('Accountexpires')) {
                    invoke-command -ComputerName $computer -Credential $Credential -ScriptBlock {
                        Set-LocalUser -Name $args[0] -AccountExpires $args[1] -Confirm:$false
                    } -ArgumentList $username, $Accountexpires
                }
                if ($AccountNeverExpires -eq $True) {
                    invoke-command -ComputerName $computer -Credential $Credential -ScriptBlock {
                        Set-LocalUser -Name $args[0] -AccountNeverExpires $args[1] -Confirm:$false
                    } -ArgumentList $username, $True
                }
                else {
                    invoke-command -ComputerName $computer -Credential $Credential -ScriptBlock {
                        Set-LocalUser -Name $args[0] -AccountNeverExpires $args[1] -Confirm:$false
                    } -ArgumentList $username, $false
                }
                if ($PSBoundParameters.ContainsKey('Description')) {
                    invoke-command -ComputerName $computer -Credential $Credential -ScriptBlock {
                        Set-LocalUser -Name $args[0] -Description $args[1] -Confirm:$false
                    } -ArgumentList $username, $Description
                }
                if ($PSBoundParameters.ContainsKey('Password')) {
                    invoke-command -ComputerName $computer -Credential $Credential -ScriptBlock {
                        Set-LocalUser -Name $args[0] -Password $args[1] -Confirm:$false
                    } -ArgumentList $username, $Password
                }
                if ($PasswordNeverExpires -eq $true) {
                    invoke-command -ComputerName $computer -Credential $Credential -ScriptBlock {
                        Set-LocalUser -Name $args[0] -PasswordNeverExpires $args[1] -Confirm:$false
                    } -ArgumentList $username, $True
                }
                else {
                    invoke-command -ComputerName $computer -Credential $Credential -ScriptBlock {
                        Set-LocalUser -Name $args[0] -PasswordNeverExpires $args[1] -Confirm:$false
                    } -ArgumentList $username, $false
                }
                if ($UserMayChangePassword -eq $true) {
                    invoke-command -ComputerName $computer -Credential $Credential -ScriptBlock {
                        Set-LocalUser -Name $args[0] -UserMayChangePassword $args[1] -Confirm:$false
                    } -ArgumentList $username, $True
                }
                else {
                    invoke-command -ComputerName $computer -Credential $Credential -ScriptBlock {
                        Set-LocalUser -Name $args[0] -UserMayChangePassword $args[1] -Confirm:$false
                    } -ArgumentList $username, $false
                }
            }
            else {
                if ($PSBoundParameters.ContainsKey('FullName')) {
                    invoke-command -ComputerName $computer -ScriptBlock {
                        Set-LocalUser -Name $args[0] -FullName $args[1] -Confirm:$false
                    } -ArgumentList $username, $FullName
                }
                if ($PSBoundParameters.ContainsKey('Accountexpires')) {
                    invoke-command -ComputerName $computer -ScriptBlock {
                        Set-LocalUser -Name $args[0] -AccountExpires $args[1] -Confirm:$false
                    } -ArgumentList $username, $Accountexpires
                }
                if ($AccountNeverExpires -eq $True) {
                    invoke-command -ComputerName $computer -ScriptBlock {
                        Set-LocalUser -Name $args[0] -AccountNeverExpires $args[1] -Confirm:$false
                    } -ArgumentList $username, $True
                }
                else {
                    invoke-command -ComputerName $computer -ScriptBlock {
                        Set-LocalUser -Name $args[0] -AccountNeverExpires $args[1] -Confirm:$false
                    } -ArgumentList $username, $false
                }
                if ($PSBoundParameters.ContainsKey('Description')) {
                    invoke-command -ComputerName $computer -ScriptBlock {
                        Set-LocalUser -Name $args[0] -Description $args[1] -Confirm:$false
                    } -ArgumentList $username, $Description
                }
                if ($PSBoundParameters.ContainsKey('Password')) {
                    invoke-command -ComputerName $computer -ScriptBlock {
                        Set-LocalUser -Name $args[0] -Password $args[1] -Confirm:$false
                    } -ArgumentList $username, $Password
                }
                if ($PasswordNeverExpires -eq $true) {
                    invoke-command -ComputerName $computer -ScriptBlock {
                        Set-LocalUser -Name $args[0] -PasswordNeverExpires $args[1] -Confirm:$false
                    } -ArgumentList $username, $True
                }
                else {
                    invoke-command -ComputerName $computer -ScriptBlock {
                        Set-LocalUser -Name $args[0] -PasswordNeverExpires $args[1] -Confirm:$false
                    } -ArgumentList $username, $false
                }
                if ($UserMayChangePassword -eq $true) {
                    invoke-command -ComputerName $computer -ScriptBlock {
                        Set-LocalUser -Name $args[0] -UserMayChangePassword $args[1] -Confirm:$false
                    } -ArgumentList $username, $True
                }
                else {
                    invoke-command -ComputerName $computer -ScriptBlock {
                        Set-LocalUser -Name $args[0] -UserMayChangePassword $args[1] -Confirm:$false
                    } -ArgumentList $username, $false
                }
            }
        }
        else {
            Write-Warning "$Computer offline."
        }
    }
} #Review - testing, Documentation
function Set-SHDComputerSpeaker {
    [cmdletbinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Provide the target hostname",
            Mandatory = $true)][Alias('Hostname', 'cn')][String[]]$Computername,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential,
        [Parameter(Helpmessage = "Increase volume by", Mandatory = $true)][int]$Volume
    )
    foreach ($computer in $Computername) {
        if (Test-Connection -ComputerName $computer -Count 1 -Quiet) {
            try {
                if ($PSBoundParameters.ContainsKey('Credential')) {
                    Invoke-Command -ComputerName $computer -Credential $Credential {
                        $Obj = New-Object -com wscript.shell
                        1..100 | foreach-object { $obj.sendkeys([char]174) }
                        0..$Volume | foreach-object { $obj.sendkeys([char]175) }
                    }
                }
                else {
                    Invoke-Command -ComputerName $computer {
                        $Obj = New-Object -com wscript.shell
                        1..100 | foreach-object { $obj.sendkeys([char]174) }
                        0..$Volume | foreach-object { $obj.sendkeys([char]175) }
                    }
                }
            }
            catch {
                Write-Warning "Unable to capture Data from $Computer."
            }
        }
        else {
            Write-Warning "$Computer is offline."
        }
    }
} #Review - Testing, Documentation
function Set-SHDComputerToUseWSUSserver {
    [cmdletbinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Provide the target hostname",
            Mandatory = $true)][Alias('Hostname', 'cn')][String[]]$Computername,
        [parameter(mandatory = $True)][validateset("Enable", "Disable")][string]$Command,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )
    foreach ($Computer in $ComputerName) {
        if (Test-Connection -ComputerName $Computer -Quiet -Count 1) {
            if ($PSBoundParameters.ContainsKey('Credential')) {
                if ($Command -eq "Enable") {
                    Invoke-Command -ComputerName $Computer -Credential $Credential -ScriptBlock {
                        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'UseWUServer' -Value 1
                        Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'UseWUServer' | Select-Object PSComputerName, UseWUServer
                    }
                } 
                if ($Command -eq "Disable") {
                    Invoke-Command -ComputerName $Computer -Credential $Credential -ScriptBlock {
                        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'UseWUServer' -Value 0
                        Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'UseWUServer' | Select-Object PSComputerName, UseWUServer
                    }        
                }
            }
            else {
                if ($Command -eq "Enable") {
                    Invoke-Command -ComputerName $Computer -ScriptBlock {
                        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'UseWUServer' -Value 1
                        Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'UseWUServer' | Select-Object PSComputerName, UseWUServer
                    }
                } 
                if ($Command -eq "Disable") {
                    Invoke-Command -ComputerName $Computer -ScriptBlock {
                        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'UseWUServer' -Value 0
                        Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'UseWUServer' | Select-Object PSComputerName, UseWUServer
                    }        
                }
            }
        }
        else {
            Write-Warning "$Computer Offline"
        }
    }
} #Review - Test, Documentation
function Get-SHDComputerLocalGroupMember {
    [cmdletbinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Provide the target hostname",
            Mandatory = $true)][Alias('Hostname', 'cn')][String[]]$Computername,
        [Parameter(HelpMessage = "Target Group", Mandatory = $True)][String[]]$GroupName,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )
    foreach ($computer in $Computername) {
        if (Test-Connection -ComputerName $computer -Count 1 -Quiet) {
            foreach ($Group in $GroupName) {
                Foreach ($User in $username) {
                    try {
                        if ($PSBoundParameters.ContainsKey('Credential')) {
                            Invoke-Command -ComputerName $computer -Credential $Credential -ScriptBlock {
                                Get-LocalGroupMember -Group $args[0]
                            } -ArgumentList $Group, $User | Select-Object PScomputername, ObjectClass, name, principalsource
                        }
                        else {
                            Invoke-Command -ComputerName $computer -ScriptBlock {
                                Get-LocalGroupMember -Group $args[0]
                            } -ArgumentList $Group, $User | Select-Object PScomputername, ObjectClass, name, principalsource
                        }
                    }
                    catch {
                        Write-Warning "Unable to access $computer information."
                    }
                }
            }
        }
        else {
            Write-Warning "$Computer offline."
        }
    }
} #Review - testing, Documentation
function New-SHDComputerLocalGroup {
    [cmdletbinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Provide the target hostname",
            Mandatory = $true)][Alias('Hostname', 'cn')][String[]]$Computername,
        [Parameter(HelpMessage = "Target Group", Mandatory = $True)][String]$Name,
        [parameter(HelpMessage = "Group Type", Mandatory = $True)][string]$Description,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )
    foreach ($computer in $Computername) {
        if (Test-Connection -ComputerName $computer -Count 1 -Quiet) {
            if ($PSBoundParameters.ContainsKey('Credential')) {
                invoke-command -ComputerName $computer -Credential $Credential -ScriptBlock {
                    try { $Temp = Get-LocalGroup -Name $args[0] }
                    catch { $Temp = $null }
                    if ($null -eq $Temp) {
                        New-LocalGroup -Name $args[0] -Description $args[1] -Confirm:$false
                        Get-LocalGroup -Name $args[0]
                    }
                } -ArgumentList $name, $Description
            }
            else {
                invoke-command -ComputerName $computer -ScriptBlock {
                    try { $Temp = Get-LocalGroup -Name $args[0] }
                    catch { $Temp = $null }
                    if ($null -eq $Temp) {
                        New-LocalGroup -Name $args[0] -Description $args[1] -Confirm:$false
                        Get-LocalGroup -Name $args[0]
                    }
                } -ArgumentList $name, $Description
            }
        }
        else {
            Write-Warning "$Computer offline."
        }
    }

} #Review - Testing, Documentation
#-------------------------Computer - Set -----------------------------------#
Function Get-SHDIPGeoLocation {
    [cmdletbinding()]
    param (
        [parameter(HelpMessage = "Enter an IP address", Mandatory = $true)][alias("IPaddress")][ipaddress]$IP
    )
    
    Invoke-RestMethod -Method Get -Uri "http://api.ipstack.com/$($IP)?access_key=$($Token)" | Select-Object IP, Type, Continent_name, Country_Name, Region_Name, City, Zip, Latitude, Longitude
} #Review - Testing, Docunentation

function Invoke-SHDEditRemoteFile {
    [cmdletbinding()]
    param (
        [string]$FilePath
    )
    notepad.exe $FilePath
}
function Invoke-SHDLogoffUser {
    <#
.SYNOPSIS
.DESCRIPTION
.PARAMETER
.EXAMPLE
.INPUTS
.OUTPUTS
.NOTES
.LINK
#>
    [cmdletbinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Provide the target hostname",
            Mandatory = $true)][Alias('Hostname', 'cn')][String[]]$Computername,
        [parameter(HelpMessage = "Usernames you wish to log off.")][Alias("User", "Samaccountname")][string[]]$Username,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )
    foreach ($computer in $Computername) {
        if (Test-Connection -ComputerName $computer -Count 1 -Quiet) {
            foreach ($User in $Username) {
                if ($PSBoundParameters.ContainsKey('Credential')) {
                    Invoke-Command -ComputerName $Computer -Credential $Credential -ScriptBlock {
                        $Test = (((quser /server:"$($args[0])" 2> $null) -replace '^>', '') -replace '\s{2,}', ',') | ForEach-Object {
                            if ($_.Split(',').Count -eq 5) {
                                Write-Output ($_ -replace '(^[^,]+)', '$1,')
                            }
                            else {
                                Write-Output $_
                            }
                        } | ConvertFrom-Csv 
                        $Test | Where-Object { $_."IDLE TIME" -like "." } | ForEach-Object { $_."IDLE TIME" = $null } 
                        Foreach ($T in $Test) {
                            if ($T.Username -like "$($args[1])") {
                                logoff /server:"$($args[0])" $T.ID
                            }
                        }
                    } -ArgumentList $Computer, $user
                    
                }
                else {
                    Invoke-Command -ComputerName $Computer -ScriptBlock {
                        $Test = (((quser /server:"$($args[0])" 2> $null) -replace '^>', '') -replace '\s{2,}', ',') | ForEach-Object {
                            if ($_.Split(',').Count -eq 5) {
                                Write-Output ($_ -replace '(^[^,]+)', '$1,')
                            }
                            else {
                                Write-Output $_
                            }
                        } | ConvertFrom-Csv 
                        $Test | Where-Object { $_."IDLE TIME" -like "." } | ForEach-Object { $_."IDLE TIME" = $null } 
                        Foreach ($T in $Test) {
                            if ($T.Username -like "$($args[1])") {
                                logoff /server:"$($args[0])" $T.ID
                            }
                        }
                    } -ArgumentList $Computer, $user
                }
            }
            if ($PSBoundParameters.ContainsKey('Credential')) {
                Get-SHDComputerCurrentUser -Computername $computer -Credential $Credential
            }
            else {
                Get-SHDComputerCurrentUser -Computername $computer
            }
        }
        else {
            Write-Warning "$Computer is offline."
        }
    }
} #Review - Testing, Documentation
function invoke-SHDLogOffDisconnectedUsers {
    [cmdletbinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Provide the target hostname",
            Mandatory = $true)][Alias('Hostname', 'cn')][String[]]$Computername,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )
    foreach ($Computer in $Computername) {
        if ($PSBoundParameters.ContainsKey('Credential')) {
            Invoke-SHDLogoffUser -Credential $Credential -Computername $Computer -Username (Get-SHDComputerCurrentUser -Credential $Credential -Computername $Computer | Where-Object { $_.state -like "disc" }).username
        }
        else {
            Invoke-SHDLogoffUser -Computername $Computer -Username (Get-SHDComputerCurrentUser -Computername $Computer | Where-Object { $_.state -like "disc" }).username
        }
    }
}
function Format-SHDCSCDatabase {
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
                    Invoke-Command -ComputerName $computer -Credential $Credential -ScriptBlock {
                        cmd "reg add HKLM\SYSTEM\CurrentControlSet\services\CSC\Parameters /v FormatDatabase /t REG_DWORD /d 1"
                    }
                }
                else {
                    Invoke-Command -ComputerName $computer -ScriptBlock {
                        cmd "reg add HKLM\SYSTEM\CurrentControlSet\services\CSC\Parameters /v FormatDatabase /t REG_DWORD /d 1"
                    }
                }
            }
            catch {
                Write-Warning "Unable to complete task on $Computer."
            }
        }
    }
    else {
        Write-Warning "$Computer is offline."
    }
}

#--------------------------------------Printer-------------------------------------------#

function Find-SHDPrinterNameByIP {
    [cmdletbinding()]
    param (
        [parameter(HelpMessage = "IP address of the printer in question.", Mandatory = $true)][alias('IP')][IPaddress]$IPaddress,
        [parameter(HelpMessage = "Computer with the printer attached.", Mandatory = $true)][alias('Computername', 'Computer')][string]$PrintServer
    )
    $printers = Get-Printer -ComputerName $PrintServer
    $PrinterPort = @()
    foreach ($print in $printers) {
        $PrinterPort += Get-PrinterPort -ComputerName $PrintServer -Name $Print.portname | Select-Object @{L = "Name"; e = { $Print.name } }, PrinterHostAddress
    }
    $PrinterPort | Where-Object { $_.PrinterHostAddress -like $IPaddress } 
}
Function Find-SHDPrinterNameByHostName {
    [cmdletbinding()]
    param (
        [parameter(HelpMessage = "Hostname of Target Printer", Mandatory = $true)][alias('Name', 'DNSName')][String]$Hostname,
        [parameter(HelpMessage = "Computer with the printer attached.", Mandatory = $true)][alias('Computername', 'Computer')][string]$PrintServer
    )
    $Return = @()
    $IPaddress = (Resolve-DnsName -Name $HostName).IPAddress
    $Printers = Get-Printer -ComputerName $PrintServer
    foreach ($Print in $Printers) {
        $Return += Get-PrinterPort -ComputerName $PrintServer -Name $Print.portname | Select-Object @{L = "Name"; e = { $Print.name } }, PrinterHostAddress
    }
    $Return | Where-Object { $_.PrinterHostAddress -like $IPaddress } 
}
function Find-SHDPrinterByName {
    [cmdletbinding()]
    param (
        [parameter(HelpMessage = "Hostname of Target Printer", Mandatory = $true)][alias('Name', 'Printername')][String]$name,
        [parameter(HelpMessage = "Computer with the printer attached.", Mandatory = $true)][alias('Computername', 'Computer')][string]$PrintServer
    )
    Try {
        $Printer = Get-Printer -ComputerName $PrintServer -Name "$Name"
        $Port = Get-PrinterPort -ComputerName $PrintServer -Name $Printer.portname
        $Hostname = [System.Net.Dns]::gethostentry($Port.PrinterHostAddress)
        [pscustomobject]@{
            Name      = $Printer.Name
            IPAddress = $Port.PrinterHostAddress
            DNSName   = $Hostname.HostName
        }
    }
    catch {
        Write-Host "$Name Not on print server."
    }
}
function Clear-SHDPrintJobs {
    [cmdletbinding()]
    param (
        [parameter(HelpMessage = "Target Printer", Mandatory = $true)][alias('Name', 'Printername')][String[]]$name,
        [parameter(HelpMessage = "Computer with the printer attached.", Mandatory = $true)][alias('Computername', 'Computer')][string[]]$PrintServer
    )
    foreach ($Print in $PrintServer) {
        foreach ($N in $name) {
            $Printers = Get-Printer -ComputerName $Print -Name "*$N*"
            Foreach ($Printer in $Printers) {
                $Printer | Get-PrintJob | Remove-PrintJob
            } 
        }
    }
}
function Get-SHDAllPrinters {
    [cmdletbinding()]
    param (
        [parameter(HelpMessage = "Computer with the printer attached.", Mandatory = $true)][alias('Computername', 'Computer')][string]$PrintServer
    )
    $Printers = Get-Printer -ComputerName $PrintServer -Full
    foreach ($Printer in $Printers) {
        $Port = Get-PrinterPort -ComputerName $PrintServer -Name $Printer.portname 
        Try { $Hostname = [System.Net.Dns]::gethostentry($Port.PrinterHostAddress) }
        Catch { $Hostname = "" }
        [pscustomobject]@{
            DNSName        = $Hostname.HostName
            Name           = $Printer.Name
            Shared         = $printer.Shared
            SharedName     = $printer.ShareName
            PortName       = $Printer.PortName
            DriverName     = $Printer.Drivername
            Location       = $Printer.Location
            PrintProcessor = $Printer.PrintProcessor 
            Published      = $Printer.Published
            IP             = $Port.PrinterHostAddress
            PortNumber     = $PortIP.PortNumber
        }
    }
}

#--------------------------------------User/Groups---------------------------------------#
#--------------------------------------User - Get----------------------------------------#
function Get-SHDUsername {
    [cmdletbinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Enter a users Name",
            Mandatory = $true)][Alias('Hostname', 'cn')][String[]]$Idenity,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )
    if ($PSBoundParameters.ContainsKey('Credential')) {
        if ($null -eq $Name) {
            try {
                $Name = (Get-ADUser -Filter "name -like '$Idenity'" -Properties Samaccountname -Credential $Credential).samaccountname | Sort-Object
                Write-Verbose "Testing Name"
            }
            catch {
                Write-Verbose "Name Failed"
                $Name = $null
            }
        }
        if ($null -eq $Name) {
            try {
                $Name = (Get-ADUser -Filter "GivenName -like '$Idenity'" -Properties Samaccountname -Credential $Credential).samaccountname | Sort-Object
                Write-Verbose "Testing GivenName"
            }
            catch {
                Write-Verbose "GivenName Failed"
                $Name = $null
            }
        }
        if ($null -eq $Name) {
            try {
                $Name = (Get-ADUser -Filter "Surname -like '$Idenity'" -Properties Samaccountname -Credential $Credential).samaccountname | Sort-Object
                Write-Verbose "Testing Surname"
            }
            catch {
                Write-Verbose "Surname Failed"
                $Name = $null
            }
        }
        if ($null -eq $Name) {
            try {
                $Name = (Get-ADUser -Filter "SID -like '$Idenity'" -Properties Samaccountname -Credential $Credential).samaccountname | Sort-Object
                Write-Verbose "Testing SID"
            }
            catch {
                Write-Verbose "Failed SID"
                $Name = $null
            }
        }
        if ($null -eq $Name) {
            try {
                $Name = (Get-ADUser -Filter "DistinguishedName -like '*$Idenity*'" -Properties Samaccountname -Credential $Credential).samaccountname | Sort-Object
                Write-Verbose "Testing DistinguishedName"
            }
            catch {
                Write-Verbose "Failed Distinguishedname"
                $Name = $null
            }
        }
        if ($null -eq $Name) {
            try {
                $Name = (Get-ADUser -Filter "SamAccountName -like '*$Idenity*'" -Properties Samaccountname -Credential $Credential).samaccountname | Sort-Object
                Write-Verbose "Testing Samaccountname"
            }
            catch {
                Write-Verbose "Failed Samaccountname"
                $Name = $null
            }
        }
        if ($null -eq $Name) {
            try {
                $Name = (Get-ADUser -Filter "ObjectGUID -like '*$Idenity*'" -Properties Samaccountname -Credential $Credential).samaccountname | Sort-Object
                Write-Verbose "Testing ObjectGUID"
            }
            catch {
                Write-Verbose "Failed ObjectGUID"
                $Name = $null
            }
        }
        if ($null -eq $Name) {
            try {
                $Name = (Get-ADUser -Filter * -Properties Samaccountname, EmployeeID -Credential $Credential | Where-Object { $_.EmployeeID -like "*$Idenity*" }).samaccountname | Sort-Object
                Write-Verbose "Testing EmployeeID"
            }
            catch {
                Write-Verbose "Failed EmployeeID"
                $Name = $null
            }
        }
        if ($null -eq $Name) {
            try {
                $Name = (Get-ADUser -Filter * -Properties Samaccountname, EmployeeNumber -Credential $Credential | Where-Object { $_.EmployeeNumber -like "*$Idenity*" }).samaccountname | Sort-Object
                Write-Verbose "Testing EmployeeNumber"
            }
            catch {
                Write-Verbose "Failed EmployeeNumber"
                $Name = $null
            }
        }
        if ($null -eq $Name) {
            try {
                $Name = (Get-ADUser -Filter * -Properties Samaccountname, Office -Credential $Credential | Where-Object { $_.Office -like "*$Idenity*" }).samaccountname | Sort-Object
                Write-Verbose "Testing Office"
            }
            catch {
                Write-Verbose "Failed Office"    
                $Name = $null
            }
        }
        if ($null -eq $Name) {
            try {
                $Name = (Get-ADUser -Filter * -Properties Samaccountname, EmailAddress -Credential $Credential | Where-Object { $_.EmailAddress -like "*$Idenity*" }).samaccountname | Sort-Object
                Write-Verbose "Testing Email Address"
            }
            catch {
                Write-Verbose "Failed EmailAddress"
                $Name = $null
            }
        }
        if ($null -eq $Name) {
            try {
                $Name = (Get-ADUser -Filter * -Properties Samaccountname, Department -Credential $Credential | Where-Object { $_.Department -like "*$Idenity*" }).samaccountname | Sort-Object
                Write-Verbose "Testing Department"
            }
            catch {
                Write-Verbose "Failed Department"
                $Name = $null
            }
        }
        if ($null -eq $Name) {
            try {
                $Name = (Get-ADUser -Filter * -Properties Samaccountname, City -Credential $Credential | Where-Object { $_.City -like "*$Idenity*" }).samaccountname | Sort-Object
                Write-Verbose "Testing City"
            }
            catch {
                Write-Verbose "You failed this city"
                $Name = $null
            }
        }
        if ($null -eq $Name) {
            write-warning "Can not find $Idenity"
        }
        else {
            $Name
        }
    }
    else {
        if ($null -eq $Name) {
            try {
                $Name = (Get-ADUser -Filter "name -like '$Idenity'" -Properties Samaccountname).samaccountname | Sort-Object
                Write-Verbose "Testing Name"
            }
            catch {
                Write-Verbose "Name Failed"
                $Name = $null
            }
        }
        if ($null -eq $Name) {
            try {
                $Name = (Get-ADUser -Filter "GivenName -like '$Idenity'" -Properties Samaccountname).samaccountname | Sort-Object
                Write-Verbose "Testing GivenName"
            }
            catch {
                Write-Verbose "GivenName Failed"
                $Name = $null
            }
        }
        if ($null -eq $Name) {
            try {
                $Name = (Get-ADUser -Filter "Surname -like '$Idenity'" -Properties Samaccountname).samaccountname | Sort-Object
                Write-Verbose "Testing Surname"
            }
            catch {
                Write-Verbose "Surname Failed"
                $Name = $null
            }
        }
        if ($null -eq $Name) {
            try {
                $Name = (Get-ADUser -Filter "SID -like '$Idenity'" -Properties Samaccountname).samaccountname | Sort-Object
                Write-Verbose "Testing SID"
            }                 
            catch {
                Write-Verbose "Failed SID"
                $Name = $null
            }
        }
        if ($null -eq $Name) {
            try {
                $Name = (Get-ADUser -Filter "DistinguishedName -like '*$Idenity*'" -Properties Samaccountname).samaccountname | Sort-Object
                Write-Verbose "Testing DistinguishedName"
            }
            catch {
                Write-Verbose "Failed Distinguishedname"
                $Name = $null
            }
        }
        if ($null -eq $Name) {
            try {
                $Name = (Get-ADUser -Filter "SamAccountName -like '*$Idenity*'" -Properties Samaccountname).samaccountname | Sort-Object
                Write-Verbose "Testing Samaccountname"
            }
            catch {
                Write-Verbose "Failed Samaccountname"
                $Name = $null
            }
        }
        if ($null -eq $Name) {
            try {
                $Name = (Get-ADUser -Filter "ObjectGUID -like '*$Idenity*'" -Properties Samaccountname).samaccountname | Sort-Object
                Write-Verbose "Testing ObjectGUID"
            }
            catch {
                Write-Verbose "Failed ObjectGUID"
                $Name = $null
            }
        }
        if ($null -eq $Name) {
            try {
                $Name = (Get-ADUser -Filter * -Properties Samaccountname, EmployeeID | Where-Object { $_.EmployeeID -like "*$Idenity*" }).samaccountname | Sort-Object
                Write-Verbose "Testing EmployeeID"
            }
            catch {
                Write-Verbose "Failed EmployeeID"
                $Name = $null
            }
        }
        if ($null -eq $Name) {
            try {
                $Name = (Get-ADUser -Filter * -Properties Samaccountname, EmployeeNumber | Where-Object { $_.EmployeeNumber -like "*$Idenity*" }).samaccountname | Sort-Object
                Write-Verbose "Testing EmployeeNumber"
            }
            catch {
                Write-Verbose "Failed EmployeeNumber"
                $Name = $null
            }
        }
        if ($null -eq $Name) {
            try {
                $Name = (Get-ADUser -Filter * -Properties Samaccountname, Office | Where-Object { $_.Office -like "*$Idenity*" }).samaccountname | Sort-Object
                Write-Verbose "Testing Office"
            }
            catch {
                Write-Verbose "Failed Office"    
                $Name = $null
            }
        }
        if ($null -eq $Name) {
            try {
                $Name = (Get-ADUser -Filter * -Properties Samaccountname, EmailAddress | Where-Object { $_.EmailAddress -like "*$Idenity*" }).samaccountname | Sort-Object
                Write-Verbose "Testing Email Address"
            }
            catch {
                Write-Verbose "Failed EmailAddress"
                $Name = $null
            }
        }
        if ($null -eq $Name) {
            try {
                $Name = (Get-ADUser -Filter * -Properties Samaccountname, Department | Where-Object { $_.Department -like "*$Idenity*" }).samaccountname | Sort-Object
                Write-Verbose "Testing Department"
            }
            catch {
                Write-Verbose "Failed Department"
                $Name = $null
            }
        }
        if ($null -eq $Name) {
            try {
                $Name = (Get-ADUser -Filter * -Properties Samaccountname, City | Where-Object { $_.City -like "*$Idenity*" }).samaccountname | Sort-Object
                Write-Verbose "Testing City"
            }
            catch {
                Write-Verbose "You failed this city"
                $Name = $null
            }
        }
        if ($null -eq $Name) {
            write-warning "Can not find $Idenity"
        }
        else {
            $Name
        }
    }
} #Review - Testing, Documentation

#--------------------------------------User - Get----------------------------------------#
function Test-SHDPasswordSecurity {
    param(
        [Parameter(Mandatory)][securestring]$Password
    )
    $StringBuilder = New-Object System.Text.StringBuilder
    $Cred = [pscredential]::new("User", $Password)
    [System.Security.Cryptography.HashAlgorithm]::Create("SHA1").ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Cred.GetNetworkCredential().Password)) |
    ForEach-Object { [Void]$StringBuilder.Append($_.ToString("x2")) }
    $Hash = $StringBuilder.ToString()
    $First5 = $Hash.Substring(0, 5)
    $Results = (Invoke-RestMethod -Uri "https://api.pwnedpasswords.com/range/$First5").split("`n") | ForEach-Object {
        [PSCustomObject]@{
            Hash           = $First5 + $_.Split(':')[0]
            PasswordsFound = [int]($_.Split(':')[1])
        }
    }
    if ($Results.Hash -contains $Hash) {
        $Count = ($Results | Where-Object Hash -eq $Hash).PasswordsFound
        $Count
    }
} #Review - Testing, Documentation

Function Copy-SHDUserGroupToUser {
    [cmdletbinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Enter a users Name",
            Mandatory = $true)][String]$SourceUser,
        [Parameter(HelpMessage = "Target User", Mandatory = $True)][string[]]$TargetUser,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )
    foreach ($Target in $TargetUser) {
        if ($PSBoundParameters.ContainsKey('Credential')) {
            $Groups = (Get-ADUser -Identity $SourceUser -Properties memberof -Credential $Credential).memberof -Replace '^cn=([^,]+).+$', '$1' | Sort-Object | ForEach-Object { (Get-ADGroup -Filter "name -like '$_'" -Properties samaccountname -Credential $Credential).samaccountname }
            Foreach ($Target in $Target) {
                $Groups | ForEach-Object {
                    try {
                        Add-ADGroupMember -Identity $_ -Members $Target -Credential $Credential
                    }
                    catch {
                        Write-Warning "$_ could not apply to $Target"
                    }
                }
                Get-aduser -Credential $Credential -Identity $target -Properties memberof | Select-Object name, memberof
            }
        }
        else {
            $Groups = (Get-ADUser -Identity $SourceUser -Properties memberof ).memberof -Replace '^cn=([^,]+).+$', '$1' | Sort-Object | ForEach-Object { (Get-ADGroup -Filter "name -like '$_'" -Properties samaccountname).samaccountname }
            Foreach ($Target in $Target) {
                $Groups | ForEach-Object {
                    try {
                        Add-ADGroupMember -Identity $_ -Members $Target
                    }
                    catch {
                        Write-Warning "$_ could not apply to $Target"
                    }
                }
                Get-aduser -Identity $target -Properties memberof | Select-Object name, memberof
            }
        }
        
    }
} #Review - Testing, Documentation
Function Remove-SHDUserGroups {
    [cmdletbinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Enter a users Name",
            Mandatory = $true)][String[]]$Username,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )
    foreach ($user in $username) {
        if ($PSBoundParameters.ContainsKey('Credential')) {
            Try {
                $U = Get-ADUser -Identity $user -Properties memberof -Credential $Credential
            }
            catch {
                Write-Warning "$User does not exists. Please check the spelling and try again."
            }
            if ($null -ne $u) {

                $U.memberof | foreach-object { Get-ADGroup -Identity $_ | Remove-ADGroupMember -Credential $Credential -Members $U.samaccountname -Confirm:$false }
                Get-ADUser -Identity $user -Properties memberof -Credential $Credential | Select-Object name, samaccountname, memberof
            }
            else {
                Write-Warning "No data found for $user."
            }
        }
        else {
            Try {
                $U = Get-ADUser -Identity $user -Properties memberof 
            }
            catch {
                Write-Warning "$User does not exists. Please check the spelling and try again."
            }
            if ($null -ne $u) {
                $U.memberof | foreach-object { Get-ADGroup -Identity $_ | Remove-ADGroupMember -Members $U.samaccountname -Confirm:$false }
                Get-ADUser -Identity $user -Properties memberof | Select-Object name, samaccountname, memberof
            }
            else {
                Write-Warning "No data found for $user."
            }
        }
    }
} #Review - Testing, Documentation
Function Copy-SHDUserSecurityGroupsToUser {
    [cmdletbinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Enter a users Name",
            Mandatory = $true)][String]$SourceUser,
        [Parameter(HelpMessage = "Target User", Mandatory = $True)][string[]]$TargetUser,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )
    if ($PSBoundParameters.ContainsKey('Credential')) {

        (Get-ADUser -Identity sfricks -Properties memberof).memberof | Get-ADGroup | Where-Object { $_.GroupCategory -like "Security" } | ForEach-Object { Add-ADGroupMember -Identity $_ -Members knsmith -Verbose }
        $Groups = (Get-ADUser -Identity $SourceUser -Properties memberof -Credential $Credential).memberof | Get-ADGroup -Filter "name -like '$_'" -Properties samaccountname -Credential $Credential | Where-Object { $_.GroupCategory -like "Security" }
        Foreach ($Target in $Target) {
            $Groups | ForEach-Object {
                try {
                    Add-ADGroupMember -Identity $_ -Members $Target -Credential $Credential
                }
                catch {
                    Write-Warning "$_ could not apply to $Target"
                }
            }
        }
    }
    else {
        $Groups = (Get-ADUser -Identity $SourceUser -Properties memberof).memberof | Get-ADGroup -Filter "name -like '$_'" -Properties samaccountname | Where-Object { $_.GroupCategory -like "Security" }
        Foreach ($Target in $Target) {
            $Groups | ForEach-Object {
                try {
                    Add-ADGroupMember -Identity $_ -Members $Target
                }
                catch {
                    Write-Warning "$_ could not apply to $Target"
                }
            }
        }
    }
} #Review - Testing, Documentation
function Copy-SHDUserToUser {
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Enter a users Name",
            Mandatory = $true)][String]$SourceUser,
        [Parameter(HelpMessage = "Target User", Mandatory = $True)][string[]]$TargetUser,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )
    try {
        $Source = Get-ADUser -Identity $SourceUser -Properties *
    }
    catch {
        write-warning "Unable to find $SourceUser"
        break
        $Source = Get-ADUser -Identity $SourceUser -Properties *
    }
    $OU = $Source.DistinguishedName -replace '^CN=.*?,', '' 
    Foreach ($Target in $TargetUser) {
        if ($PSBoundParameters.ContainsKey('Credential')) {
            try {
                $T = Get-aduser -Identity $Target -Properties * -credential $Credential
            }
            catch {
                write-warning "Unable to find $target"
                break
            }
            Remove-SHDUsersGroups -Username $T.samaccountname  -credential $Credential
            Set-ADUser -Identity $T.samaccountname -Department $Source.department -Title $Source.Title -City $Source.city -Company $Source.Company -Country $source.country -Division $source.division -Manager $source.Manager -LogonWorkstations $Source.LogonWorkstations -Office $Source.Office -Organization $Source.Organization -POBox $Source.PObox -PostalCode $Source.PostalCode -State $source.state -StreetAddress $Source.StreetAddress -credential $Credential
            Move-ADObject -Identity $T.samaccountname -TargetPath $OU -credential $Credential
            $Source.memberof | foreach-object { Add-adgroupmemeber -Identity $_ -member $T.Samaccountname -credential $Credential }
        }
        else {
            try {
                $T = Get-aduser -Identity $Target -Properties *
            }
            catch {
                write-warning "Unable to find $target"
                break
            }
            Remove-SHDUsersGroups -Username $T.samaccountname 
            Set-ADUser -Identity $T.samaccountname -Department $Source.department -Title $Source.Title -City $Source.city -Company $Source.Company -Country $source.country -Division $source.division -Manager $source.Manager -LogonWorkstations $Source.LogonWorkstations -Office $Source.Office -Organization $Source.Organization -POBox $Source.PObox -PostalCode $Source.PostalCode -State $source.state -StreetAddress $Source.StreetAddress
            Move-ADObject -Identity $T.samaccountname -TargetPath $OU
            $Source.memberof | foreach-object { Add-adgroupmemeber -Identity $_ -member $T.Samaccountname }
        }
    }
}
function Get-SHDUserInfo {
    [cmdletbinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Provide the target Name",
            Mandatory = $true)][Alias('Identity', 'Samaccountname', 'cn')][String[]]$Username,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )
    foreach ($User in $Username) {
        if ($PSBoundParameters.ContainsKey('Credential')) {
            $Groups = Get-ADPrincipalGroupMembership -Identity $User -Credential $Credential
            $SG = $Groups | Where-Object { $_.GroupCategory -like "Security" }
            $DG = $Groups | Where-Object { $_.GroupCategory -like "Distribution" }
            $Info = Get-ADUser -Identity $User -Properties *, "msDS-UserPasswordExpiryTimeComputed"-Credential $Credential
            [pscustomobject]@{
                Name               = $Info.Name
                Samaccountname     = $Info.Samaccountname
                Department         = $Info.department
                Office             = $info.Office
                EmployeeID         = $Info.EmployeeID
                Email              = $info.Mail
                LastLogonDate      = ([datetime]$Info.lastLogonTimestamp).ToString()
                PasswordLastSet    = $info.PasswordLastSet
                PasswordExpiryDate = [datetime]::FromFileTime($info."msDS-UserPasswordExpiryTimeComputed")
                Created            = $Info.WhenCreated
                Enabled            = $Info.Enabled 
                LockedOut          = $info.LockedOut
                GroupCount         = $Groups.count 
                SecurityGroups     = $SG.name 
                DistributionGroups = $DG.Name
            }
        }
        else {
            $Groups = Get-ADPrincipalGroupMembership -Identity $User 
            $Info = Get-ADUser -Identity $User -Properties *, "msDS-UserPasswordExpiryTimeComputed"
            $SG = $Groups | Where-Object { $_.GroupCategory -like "Security" }
            $DG = $Groups | Where-Object { $_.GroupCategory -like "Distribution" }
            [pscustomobject]@{
                Name               = $Info.Name
                Samaccountname     = $Info.Samaccountname
                Department         = $Info.department
                Office             = $info.Office
                EmployeeID         = $Info.EmployeeID
                Email              = $info.Mail
                LastLogonDate      = ([datetime]$Info.lastLogonTimestamp).ToString()
                PasswordLastSet    = $info.PasswordLastSet
                PasswordExpiryDate = ([datetime]::FromFileTime($info."msDS-UserPasswordExpiryTimeComputed")).tostring()
                Created            = $Info.WhenCreated
                Enabled            = $Info.Enabled 
                LockedOut          = $info.LockedOut
                GroupCount         = $Groups.count 
                SecurityGroups     = $SG.name 
                DistributionGroups = $DG.Name
            }
        }
    }        
} #Review - Testing, Documentation
function Get-SHDUsersFromOU {
    [cmdletbinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Provide the target hostname",
            Mandatory = $true)][Alias('OU')][String[]]$OrganiziationalUnit,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )
    foreach ($OU in $OrganizationalUnit) {
        if ($PSBoundParameters.ContainsKey('Credential')) {
            try {
                Get-aduser -Filter * -SearchBase "$OU" -Credential $Credential | sort-object Name | Select-Object name, Samaccountname
            }
            catch {
                Write-Warning "Can't find $OU"
            }
        }
        else {
            try {
                Get-aduser -Filter * -SearchBase "$OU" | sort-object Name | Select-Object name, Samaccountname
            }
            catch {
                Write-Warning "Can't find $OU"
            }
        }
    }
} #Review - Testing, Documentation
Function Get-SHDLockoutInfo {
    [cmdletbinding()]
    param (
        [parameter(Helpmessage = "Days back")][Alias('day')][String]$DayCount,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )
    $FilterTable = @{
        'StartTime' = ((Get-date).AddDays( - ($DayCount)))
        'EndTime'   = (Get-date)
        'LogName'   = 'Security'
        'Id'        = 4740
    }
    
    $Servers = (Get-ADDomain).ReplicaDirectoryServers
    $Events = @()
    foreach ($server in $Servers) {
        if ($PSBoundParameters.ContainsKey('Credential')) {
            $Events += Get-WinEvent -ComputerName $server -FilterHashtable $FilterTable -Credential $Credential -ErrorAction SilentlyContinue
        }
        else {
            $Events += Get-WinEvent -ComputerName $server -FilterHashtable $FilterTable -ErrorAction SilentlyContinue
        }
    }
    foreach ($E in $Events) {
        [pscustomobject]@{
            Time     = $E.TimeCreated
            DC       = $E.Properties[4].value
            Username = $E.Properties[0].value
            Computer = $E.Properties[1].value
        }
    }
} #Review - Testing, Documentation
Function Get-SHDUserGroup {
    [cmdletbinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Provide the target hostname",
            Mandatory = $true)][Alias('Samaccountname')][String[]]$Username,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )
    foreach ($User in $Username) {
        if ($PSBoundParameters.ContainsKey('Credential')) {
            try {
                $Groups = (Get-ADUser -Identity $user -Properties memberof -Credential $Credential).memberof
                foreach ($Group in $Groups) {
                    try {
                        Get-ADGroup -Identity $Group -Credential $Credential | sort-object Name | Select-Object Name, Samaccountname, GroupScope, GroupCategory
                    }
                    catch {
                        Write-Warning "$Group can not be found."
                    }
                }
            }
            catch {
                Write-Warning "$User can not be found."
            }
            
        }
        else {
            try {
                $Groups = (Get-ADUser -Identity $user -Properties memberof).memberof
                foreach ($Group in $Groups) {
                    try {
                        Get-ADGroup -Identity $Group | sort-object Name | Select-Object Name, Samaccountname, GroupScope, GroupCategory
                    }
                    catch {
                        Write-Warning "$Group can not be found."
                    }
                }
            }
            catch {
                Write-Warning "$User can not be found."
            }
        }
    }
} #Review - Testing, Documentation
Function Get-SHDUserOUMembers {
    [cmdletbinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Target usernames",
            Mandatory = $true)][Alias('Samaccountname')][String[]]$Username,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )
    foreach ($User in $Username) {
        if ($PSBoundParameters.ContainsKey('Credential')) {
            $OU = (Get-ADUser -Identity $user -Credential $Credential).DistinguishedName -replace '^CN=.*?,', '' 
            Get-ADUser -Filter $ -SearchBase "$OU" -Credential $Credential | Select-Object Name, Samaccountname, @{l = "OU"; e = { $_.DistinguishedName -replace '^CN=.*?,', '' } }
        }
        else {
            $OU = (Get-ADUser -Identity $user).DistinguishedName -replace '^CN=.*?,', '' 
            Get-ADUser -Filter $ -SearchBase "$OU" | Select-Object Name, Samaccountname, @{l = "OU"; e = { $_.DistinguishedName -replace '^CN=.*?,', '' } }
        }
    }
} #Review - Testing, Documentation
Function Lock-SHDUser {
    [cmdletbinding()]
    param ([Parameter(ValueFromPipelineByPropertyName = $true, Mandatory = $true)][string[]]$UserName)
    Process {
        foreach ($User in $UserName) {
            $Pass = ConvertTo-SecureString "123456789DIkasoiu4i9asof84nsdida98!!!!!!" -AsPlainText -Force
            for ($i = 1; $i -le 5; $i++) {
                Invoke-Command -ComputerName dc01 -ScriptBlock { Get-Process } -Credential (New-Object System.Management.Automation.PSCredential($User, $Pass)) -ErrorAction SilentlyContinue
                Write-Verbose "$User Invoke $i times"
            }
            Get-ADUser -Identity $User -Properties Samaccountname, lockedout | Select-Object name, samaccountname, lockedout
        }
    }
} #Review - Testing, Documentation
Function Set-SHDUserPassword {
    [cmdletbinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName = $true, Mandatory = $true)][string[]]$Username,
        [Parameter(Mandatory = $true)][securestring]$Password,
        [switch]$ForceReset = $false
    )
    foreach ($user in $Username) {
        try {
            Set-ADAccountPassword -Identity $User -Reset -NewPassword (ConvertTo-SecureString -AsPlainText -String $Password -Force)
            if ($ForceReset) {
                Set-ADUser -Identity $User -ChangePasswordAtLogon $true
            }
            else {
                Set-ADUser -Identity $User -ChangePasswordAtLogon $false
            }
        }
        catch {
            Write-Warning "$User does not exists."
        }
    }
} #Review - Testing, Documentation
Function Get-SHDInactiveUsers {
    [cmdletbinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Days since last logon.",
            Mandatory = $true)][Alias('Age')][String[]]$Days,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )
    foreach ($Day in $Day) {
        if ($PSBoundParameters.ContainsKey('Credential')) {
            try {
                Get-ADUser -Credential $Credential -filter { enabled -eq $true } -Properties lastLogonTimestamp | Select-Object name, samaccountname, @{'l' = "LastLogin"; e = { [datetime]$_.lastLogonTimestamp } } | Where-Object { ($_.LastLogin -ge ((get-date).AddDays( - ($day))) -and ($null -ne $_.LastLogin)) }
            }
            catch {
                Write-Warning "Unable to access user data."
            }
        }
        else {
            try {
                Get-ADUser -filter { enabled -eq $true } -Properties lastLogonTimestamp | Select-Object name, samaccountname, @{'l' = "LastLogin"; e = { [datetime]$_.lastLogonTimestamp } } | Where-Object { ($_.LastLogin -ge ((get-date).AddDays( - ($day))) -and ($null -ne $_.LastLogin)) }
            }
            catch {
                Write-Warning "Unable to access user data."
            }
        }
    }
} #Review - Testing, Documentation
Function Unlock {
    [cmdletbinding()]
    param (
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )
    if ($PSBoundParameters.ContainsKey('Credential')) {
        $Users = Search-ADAccount -Credential $Credential -LockedOut 
        foreach ($user in $users) {
            $user | Unlock-ADAccount -Credential $Credential
            Get-ADUser -Identity $user -Properties samaccountname, lockedout -Credential $Credential | sort-object name | Select-Object name, samaccountname, lockedout
        }
    }
    else {
        $Users = Search-ADAccount -LockedOut 
        foreach ($user in $users) {
            $user | Unlock-ADAccount
            Get-ADUser -Identity $user -Properties samaccountname, lockedout | sort-object name | Select-Object name, samaccountname, lockedout
        }
    }
} #Review - Testing, Documentation
Function Get-SHDUserPasswordExpirey {
    [cmdletbinding()]
    param (
        [parameter(HelpMessage = "Number of days Back", Mandatory = $true)][alias("Age")][int]$Day
    )
    Begin {
        #Set the number of days within expiration.  This will start to send the email x number of days before it is expired.
        $DaysWithinExpiration = $Days
        #Set the days where the password is already expired and needs to change. -- Do Not Modify --
        $MaxPwdAge = (Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge.Days
        $expiredDate = (Get-Date).addDays(-$MaxPwdAge)
    
        #Set the number of days until you would like to begin notifing the users. -- Do Not Modify --
        $emailDate = (Get-Date).addDays( - ($MaxPwdAge - $DaysWithinExpiration))
    }
    Process {
        #Filters for all users who's password is within $date of expiration.
        $ExpiredUsers = Get-ADUser -Filter { (PasswordLastSet -lt $emailDate) -and (PasswordLastSet -gt $expiredDate) -and (PasswordNeverExpires -eq $false) -and (Enabled -eq $true) } -Properties DisplayName, PasswordNeverExpires, Manager, PasswordLastSet, Mail, "msDS-UserPasswordExpiryTimeComputed" -SearchBase "OU=TBC Employees, OU=TBC,DC=TBC,DC=Local" | Select-Object DisplayName, samaccountname, @{label = "Manager"; expression = { $(($_.Manager.Split(',')).split('=')[1]) } }, PasswordLastSet, @{name = "DaysUntilExpired"; Expression = { $_.PasswordLastSet - $ExpiredDate | Select-Object -ExpandProperty Days } }, @{name = "EmailAddress"; Expression = { $_.mail } }, @{Name = "ExpiryDate"; Expression = { [datetime]::FromFileTime($_."msDS-UserPasswordExpiryTimeComputed") } } | Sort-Object PasswordLastSet
    }
    end {
        $ExpiredUsers
    }
} #Review - Testing, Documentation
Function Get-SHDGroupName {
    [cmdletbinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Target Group To Remove",
            Mandatory = $true)][Alias('Group')][String[]]$GroupName,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )
    foreach ($Group in $GroupName) {
        if ($PSBoundParameters.ContainsKey('Credential')) {
            try {
                Get-ADGroup -Filter "name -like '*$Group*'" -Credential $Credential | Select-Object name, samaccountname
            }
            catch {
                Write-Warning "Unable to find $Group"
            }
        }
        else {
            try {
                Get-ADGroup -Filter "name -like '*$Group*'" | Select-Object name, samaccountname
            }
            catch {
                Write-Warning "Unable to find $Group"
            }
        }
    }
} #Review - Testing, Documentation
Function Add-SHDGroupToOU {
    [cmdletbinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Target Group To Remove",
            Mandatory = $true)][Alias('Group')][String[]]$GroupName,
        [parameter(HelpMessage = "Target OU")][Alias('OU')][string[]]$OrganizationalUnit,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )
    foreach ($Group in $GroupName) {
        $TheGroup = $null
        Try {
            $TheGroup = Get-ADGroup -Identity $Group
        }
        catch {
            Write-Warning "Error collecting $Group information"
        }
        if ($null -ne $TheGroup) {
            foreach ($OU in $OrganizationalUnit) {
                if ($PSBoundParameters.ContainsKey('Credential')) {
                    try {
                        $Users = Get-aduser -Filter * -SearchBase "$OrganizationalUnit" -Credential $Credential
                    }
                    catch {
                        Write-Warning "Error collecting Users from $OU"
                    }
                    Foreach ($user in $users) {
                        try {
                            add-ADGroupMember -Identity $TheGroup.samaccountname -Members $user.samaccountname -Confirm:$false -Credential $Credential
                        }
                        catch {
                            Write-Warning "Failed to remove $($TheGroup.samaccountname) from $($user.samaccountname)"
                        }
                    }
                }
                else {
                    try {
                        $Users = Get-aduser -Filter * -SearchBase "$OrganizationalUnit"
                    }
                    catch {
                        Write-Warning "Error collecting Users from $OU"
                    }
                    Foreach ($user in $users) {
                        try {
                            Add-ADGroupMember -Identity $TheGroup.samaccountname -Members $user.samaccountname -Confirm:$false                        
                        }
                        catch {
                            Write-Warning "Failed to remove $($TheGroup.samaccountname) from $($user.samaccountname)"
                        }
                    }
                }
            }
        }
        else {
            Write-Warning "$Group Failure"
        }
    }
} #Review - Testing, Documentation
Function Remove-SHDGroupFromOU { 
    [cmdletbinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Target Group To Remove",
            Mandatory = $true)][Alias('Group')][String[]]$GroupName,
        [parameter(HelpMessage = "Target OU")][Alias('OU')][string[]]$OrganizationalUnit,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )
    foreach ($Group in $GroupName) {
        $TheGroup = $null
        Try {
            $TheGroup = Get-ADGroup -Identity $Group
        }
        catch {
            Write-Warning "Error collecting $Group information"
        }
        if ($null -ne $TheGroup) {
            foreach ($OU in $OrganizationalUnit) {
                if ($PSBoundParameters.ContainsKey('Credential')) {
                    try {
                        $Users = Get-aduser -Filter * -SearchBase "$OrganizationalUnit" -Credential $Credential
                    }
                    catch {
                        Write-Warning "Error collecting Users from $OU"
                    }
                    Foreach ($user in $users) {
                        try {
                            Remove-ADGroupMember -Identity $TheGroup.samaccountname -Members $user.samaccountname -Confirm:$false -Credential $Credential
                        }
                        catch {
                            Write-Warning "Failed to remove $($TheGroup.samaccountname) from $($user.samaccountname)"
                        }
                    }
                }
                else {
                    try {
                        $Users = Get-aduser -Filter * -SearchBase "$OrganizationalUnit"
                    }
                    catch {
                        Write-Warning "Error collecting Users from $OU"
                    }
                    Foreach ($user in $users) {
                        try {
                            Remove-ADGroupMember -Identity $TheGroup.samaccountname -Members $user.samaccountname -Confirm:$false                        
                        }
                        catch {
                            Write-Warning "Failed to remove $($TheGroup.samaccountname) from $($user.samaccountname)"
                        }
                    }
                }
            }
        }
        else {
            Write-Warning "$Group Failure"
        }
    }
} #Review - Testing, Documentation
function Get-SHDStaticGroups {
    [cmdletbinding()]
    param (
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )
    if ($PSBoundParameters.ContainsKey('Credential')) {
        Get-ADGroup -Credential $Credential -Filter * -Properties whenChanged | Where-Object { $_.whenChanged -le ((Get-date).adddays( - (90))) } | Sort-Object whenChanged | Select-Object samaccountname, whenChanged
    }
    else {
        Get-ADGroup -Filter * -Properties whenChanged | Where-Object { $_.whenChanged -le ((Get-date).adddays( - (90))) } | Sort-Object whenChanged | Select-Object samaccountname, whenChanged
    }

} #Review - Testing, Documentation
function Get-SHDGroupEmpty {
    <#
    .SYNOPSIS
    .DESCRIPTION
    .PARAMETER
    .EXAMPLE
    .INPUTS
    .OUTPUTS
    .NOTES
    .LINK
    #>
    [cmdletbinding()]
    param (
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )
    if ($PSBoundParameters.ContainsKey('Credential')) {
        Get-ADGroup -Filter * -Properties members -Credential $Credential | Where-Object { $_.members.count -eq 0 } | Select-Object Name, Samaccountname, GroupScope, GroupCategory
    }
    else {
        Get-ADGroup -Filter * -Properties members | Where-Object { $_.members.count -eq 0 } | Select-Object Name, Samaccountname, GroupScope, GroupCategory
    }    
} #Review - Testing, Documentation
function Find-SHDDisabledUsersOU {
    <#
    .SYNOPSIS
    .DESCRIPTION
    .PARAMETER
    .EXAMPLE
    .INPUTS
    .OUTPUTS
    .NOTES
    .LINK
    #>
    [cmdletbinding()]
    param (
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )
    if ($PSBoundParameters.ContainsKey('Credential')) {
        ((Get-ADUser -filter { enabled -eq $false } -Credential $Credential).Distinguishedname -replace '^CN=.*?,', '' | Group-Object | Sort-Object -Property Count -Descending | Select-Object -First 1).name
    }
    else {
        ((Get-ADUser -filter { enabled -eq $false }).Distinguishedname -replace '^CN=.*?,', '' | Group-Object | Sort-Object -Property Count -Descending | Select-Object -First 1).name
    }
} #Review - Testing, Documentation
function New-SHDPassword {
    [cmdletbinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName = $true, Mandatory = $true)][int[]]$Lenghths
    )
    foreach ($Number in $Lenghths) {
        -join ((32..95) + (97..126) | Get-Random -Count $Number | ForEach-Object { [char]$_ })
    }
} #Review - Testing, Documentation
function invoke-SHDDisableInactiveUsers {
    [cmdletbinding()]
    param (
        [parameter(HelpMessage = "Days after", Mandatory = $True)][int]$DaysBack,
        [parameter(HelpMessage = "Moves to this OU if provided, If not, finds disable ou and moves it.")][string]$DisabledOU,
        [parameter(HelpMessage = "Moves to this OU if provided, If not, finds disable ou and moves it.", Mandatory = $true)][string]$SearchOU,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential,
        [parameter(HelpMessage = "Show results")][switch]$ShowResults
    )
    $Time = (get-date).AddDays( - ($DaysBack))
    if ($PSBoundParameters.ContainsKey('Credential')) {
        $users = Get-aduser -Filter { Enabled -eq $true } -Credential $Credential -SearchBase $SearchOU -Properties LastLogondate | Where-Object { ($_.LastLogonDate -le $Time) -and ($null -ne $_.LastLogonDate) } | Sort-Object Samaccountname
        if ($PSBoundParameters.ContainsKey('DisabledOU')) {
            $DisabledOU = $DisabledOU
        }
        else {
            $DisabledOU = Find-SHDDisabledUsersOU -Credential $Credential
        }
        foreach ($User in $users) {
            Disable-SHDUser -Username $user.samaccountname -OU $DisabledOU -Credential $Credential 
            if ($ShowResults) {
                Get-aduser -Identity $user.samaccountname -Properties LastLogonDate, Memberof -Credential $Credential | Select-Object DistinguishedName, Samaccountname, Name, Lastlogondate, Enabled, @{l = "GroupCount"; e = { $_.memberof.count } }
            }
        }
    }
    else {
        $users = Get-aduser -Filter { Enabled -eq $true } -SearchBase $SearchOU -Properties LastLogondate | Where-Object { ($_.LastLogonDate -le $Time) -and ($null -ne $_.LastLogonDate) } | sort-object Samaccountname
        if ($PSBoundParameters.ContainsKey('OU')) {
            $DisabledOU = $DisabledOU
        }
        else {
            $DisabledOU = Find-SHDDisabledUsersOU
        }
        foreach ($User in $users) {
            Disable-SHDUser -Username $user.samaccountname -OU $DisabledOU
            if ($ShowResults) {
                Get-aduser -Identity $user.samaccountname -Properties LastLogonDate, Memberof | Select-Object DistinguishedName, Samaccountname, Name, Lastlogondate, Enabled, @{l = "GroupCount"; e = { $_.memberof.count } }
            }
        }
    }
}
Function Disable-SHDUser {
    <#
    .SYNOPSIS
    .DESCRIPTION
    .PARAMETER
    .EXAMPLE
    .INPUTS
    .OUTPUTS
    .NOTES
    .LINK
    #>
    [cmdletbinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Provide the target hostname",
            Mandatory = $true)][Alias('Hostname', 'cn')][String[]]$Username,
        [parameter(HelpMessage = "Moves to this OU if provided, If not, finds disable ou and moves it.")][string]$OU,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )
    
    if ($PSBoundParameters.ContainsKey('Credential')) {
        if ($PSBoundParameters.ContainsKey('OU')) {
            $DisabledOU = $OU
        }
        else {
            $DisabledOU = Find-SHDDisabledUsersOU -Credential $Credential
        }
        
        foreach ($user in $Username) {
            $TargetUser = Get-ADUser -Identity $user -Properties * -Credential $Credential 
            $Targetuser.memberof | foreach-object { Remove-ADGroupMember -Credential $Credential -Identity $_.DistinguishedName -Members $targetuser.samaccountname -Confirm:$false }
            Set-ADUser -Identity $TargetUser.samaccountname -Department '' -Title '' -City '' -Company '' -Country '' -Description '' -Division '' -EmailAddress '' -EmployeeID '' -EmployeeNumber '' -Fax '' -Enabled $false -HomeDirectory '' -HomeDrive '' -HomePage '' -HomePhone '' -OtherName '' -Manager '' -LogonWorkstations '' -MobilePhone '' -Office '' -OfficePhone '' -Organization '' -POBox '' -PostalCode '' -ProfilePath '' -ScriptPath '' -State '' -StreetAddress '' -Credential $Credential
            $Password = -join ((32..95) + (97..126) | Get-Random -Count 90 | ForEach-Object { [char]$_ })
            Set-ADAccountPassword -Identity $TargetUser.Samaccountname -Reset -NewPassword (ConvertTo-SecureString -AsPlainText -String $Password -Force) -Credential $Credential
            Disable-ADAccount -Identity $TargetUser.samaccountname -Credential $Credential
            Move-ADObject -Identity $TargetUser.samaccountname -TargetPath $DisabledOU -Credential $Credential
        }
    }
    else {
        if ($PSBoundParameters.ContainsKey('OU')) {
            $DisabledOU = $OU
        }
        else {
            $DisabledOU = Find-SHDDisabledUsersOU
        }
        foreach ($user in $Username) {
            $TargetUser = Get-ADUser -Identity $user -Properties * 
            $Targetuser.memberof | foreach-object { Remove-ADGroupMember -Identity $_.DistinguishedName -Members $targetuser.samaccountname -Confirm:$false }
            Set-ADUser -Identity $TargetUser.samaccountname -Department '' -Title '' -City '' -Company '' -Country '' -Description '' -Division '' -EmailAddress '' -EmployeeID '' -EmployeeNumber '' -Fax '' -Enabled $false -HomeDirectory '' -HomeDrive '' -HomePage '' -HomePhone '' -OtherName '' -Manager '' -LogonWorkstations '' -MobilePhone '' -Office '' -OfficePhone '' -Organization '' -POBox '' -PostalCode '' -ProfilePath '' -ScriptPath '' -State '' -StreetAddress '' -Credential $Credential
            $Password = -join ((32..95) + (97..126) | Get-Random -Count 90 | ForEach-Object { [char]$_ })
            Set-ADAccountPassword -Identity $TargetUser.Samaccountname -Reset -NewPassword (ConvertTo-SecureString -AsPlainText -String $Password -Force)
            Disable-ADAccount -Identity $TargetUser.samaccountname 
            Move-ADObject -Identity $TargetUser.samaccountname -TargetPath $DisabledOU 
        }
    }
} #Review - Testing, Documentation
Function Hide-SHDUsersFromGAL {
    [cmdletbinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Provide the target hostname")][Alias('Samaccountname')][String[]]$Username,
        [Parameter(HelpMessage = "Hides all disabled mailboxes")][switch]$Disabled,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )
    if (($null -eq $Username) -and ($Disabled -eq $false)) { Write-Warning "No action taken as no targets selected. Please input a username or select the disabled switch."; break }
    if ($PSBoundParameters.ContainsKey('Credential')) {
        foreach ($user in $Username) {
            try {
                Get-ADUser -Credential $Credential -Identity $user -Properties enabled, msExchHideFromAddressLists | Set-ADUser -Credential $Credential -Add @{msExchHideFromAddressLists = "TRUE" }
            }
            catch {
                Write-Warning "Failed to hide $User"
            }
        }
        if ($Disabled) { Get-ADUser -Credential $Credential -Filter { (enabled -eq "false") -and (msExchHideFromAddressLists -notlike "*") } -Properties enabled, msExchHideFromAddressLists | Sort-Object name | ForEach-Object { Set-aduser -Credential $Credential -Identity $_.samaccountname -Add @{msExchHideFromAddressLists = "TRUE" } -Verbose } }
    }
    else {
        foreach ($user in $Username) {
            try {
                Get-ADUser -Identity $user -Properties enabled, msExchHideFromAddressLists | Set-ADUser -Add @{msExchHideFromAddressLists = "TRUE" }
            }
            catch {
                Write-Warning "Failed to hide $User"
            }
        }
        if ($Disabled) { Get-ADUser -Filter { (enabled -eq "false") -and (msExchHideFromAddressLists -notlike "*") } -Properties enabled, msExchHideFromAddressLists | Sort-Object name | ForEach-Object { Set-aduser -Identity $_.samaccountname -Add @{msExchHideFromAddressLists = "TRUE" } -Verbose } }
    }
} #Review - Testing, Documentation

#-----------------------Emails
function import-SHDExchange {
    [cmdletbinding()]
    param (
        [Parameter(HelpMessage = "The Fully Quailified Domain Name of the Exchange Server.", Mandatory = $true)][string]$Servername,
        [Parameter(HelpMessage = "Allows for custom Credential.", Mandatory = $true)][System.Management.Automation.PSCredential]$Credential
    )
    do {
        $Script:Session = New-PSSession -Name exchange -ConfigurationName Microsoft.Exchange -ConnectionUri "http://$($Servername)/powershell" -Authentication Kerberos -Credential $Credential
    } until (Get-PSSession -Name exchange)
    Import-PSSession $Script:Session
} #Review - Testing, Documentation
function Get-SHDEmailAddressValidation {
    [cmdletbinding()]
    param (
        [string]$Email
    )
    $EmailRegex = '^([\w-\.]+)@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([\w-]+\.)+))([a-zA-Z]{2,4}|[0-9]{1,3})(\]?)$'
    $Email -match $EmailRegex
} #Review - Testing, Documentation
function Send-SHDMessage {
    [cmdletbinding()]
    param (
        [Parameter(HelpMessage = "Allows for custom Credential.", Mandatory = $True)][string[]]$users,
        [Parameter(HelpMessage = "The Message to send.", Mandatory = $True)][String]$Message,
        [Parameter(HelpMessage = "The Reply email.", Mandatory = $True)][String]$SenderEmail,
        [Parameter(HelpMessage = "The Name of the sender.", Mandatory = $True)][string]$Sendername,
        [Parameter(HelpMessage = "Message subject.", Mandatory = $True)][String]$Subject,
        [Parameter(HelpMessage = "Mail Server.", Mandatory = $True)][string]$MailServer,
        [Parameter(HelpMessage = "Allows for custom Credential.", Mandatory = $True)][System.Management.Automation.PSCredential]$Credential
    )
    foreach ($user in $users) {
        $TheUser = Get-ADUser -Identity $user -Properties *
        if ($TheUser.Enabled -eq $true) {
            $htmlbody = @" 
<html> 
<style>
body {background-color:#ffffff;}
table {border: 1px solid rgb(104,107,112); text-align: left;}
th {background-color: #d2e3f7;border-bottom:2px solid rgb(79,129,189);text-align: left;}
tr {border-bottom:2px solid rgb(71,85,112);text-align: left;}
td {border-bottom:1px solid rgb(99,105,112);text-align: left;}
</style>
<body style="font-family:verdana;font-size:13"> 
<p>
Dear $($TheUser.Name),<br><br>
$Message<br><br>
Thank you, <br><br>
$Sendername
<br>
<p>

</body> 
</html> 
"@
            Send-MailMessage -To $TheUser.mail -From "$Sendername <$SenderEmail>" -Subject "Screen Lockout Policy" -BodyAsHtml $htmlbody -SmtpServer $MailServer -Credential $Credential
        }
        else {
            $TheUser.SamAccountName
        }
    }
} #Review - Testing, Documentation
function Set-SHDUserForwarder {
    [cmdletbinding()]
    param (
        [Parameter(HelpMessage = "Username of the Mailbox you wish to forward to.", Mandatory = $True)][string[]]$Username,
        [Parameter(HelpMessage = "Target Mailbox that will receive the email", Mandatory = $True)][string]$Recieving,
        [switch]$DeliverToMailboxandForward
    )
    If (Get-Command 'get-mailbox') {
        foreach ($User in $Username) {
            If ($DeliverToMailboxandForward) {
                try {
                    $Mailbox = get-mailbox -identity $User
                    $Mailbox | set-mailbox -DeliverToMailboxAndForward $true -ForwardingAddress $Recieving
                    get-mailbox -identity $User | Select-Object Alias, ForwardingAddress, DeliverToMailboxandForward
                }
                catch {
                    Write-Warning "Failed to set mailbox forwarder"
                }
            }
            else {
                ry {
                    $Mailbox = get-mailbox -identity $User
                    $Mailbox | set-mailbox -DeliverToMailboxAndForward $false -ForwardingAddress $Recieving
                    get-mailbox -identity $User | Select-Object Alias, ForwardingAddress, DeliverToMailboxandForward
                } catch {
                    Write-Warning "Failed to set mailbox forwarder"
                }
            }
        }
    }
    else {
        Write-Warning "This script requires Exchange to be loaded. Use Import-SDHExchange to load exchange."
    }
} #Review - Testing, Documentation
function Clear-SHDUserForwarder {
    [cmdletbinding()]
    param (
        [Parameter(HelpMessage = "Username of the Mailbox you wish to forward to.", Mandatory = $True)][string[]]$Username
    )
    If (Get-Command 'get-mailbox') {
        foreach ($User in $Username) {
            try {
                $Mailbox = get-mailbox -identity $User
                $Mailbox | set-mailbox -DeliverToMailboxAndForward $false -ForwardingAddress $null
                get-mailbox -identity $User | Select-Object Alias, ForwardingAddress, DeliverToMailboxandForward
            }
            catch {
                Write-Warning "Failed to set mailbox forwarder"
            }
        }
    }
    else {
        Write-Warning "This script requires Exchange to be loaded. Use Import-SDHExchange to load exchange."
    }
} #Review - Testing, Documentation

#--------------------------------------------------------GPO

function Get-SHDGPOName {
    <#
		.SYNOPSIS
		    Finds a group policy by a name given.
		.DESCRIPTION
		    If you can't remember a group policy's full name, yo ucan find it with this script. 
        .PARAMETER GroupPolicyName
            The name you are searching for. 
		.EXAMPLE
            Get-GPOName -GroupPolicyName "Firewall"

            Finds the group policy with the matching name. 
            
            DisplayName      : Domain Firewall
            DomainName       : Domain
            Owner            : User
            Id               : 00000000-0000-0000-0000-000000000000
            GpoStatus        : AllSettingsEnabled
            Description      :
            CreationTime     : 7/9/2003 11:03:33 AM
            ModificationTime : 7/9/2003 12:55:20 PM
            UserVersion      :
            ComputerVersion  :
            WmiFilter        :
		.LINK
		    https://github.com/boldingdp/
		.NOTES
            Author: David Bolding
            Site: https://github.com/boldingdp/
	#> 
    [CmdletBinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Provide the target hostname",
            Mandatory = $true)]
        [Alias('GroupPolicy', 'GPO', 'ID')][String]$GroupPolicyName
    )
    $AllGPOs = Get-GPO -All    
    $AllGPOs | Where-Object { $_.DisplayName -like "*$GroupPolicyName*" }
}
function Search-SHDUsersOnComputerForGPO {
    <#
		.SYNOPSIS
		    Finds all users with a given gpo name on target server.
		.DESCRIPTION
		    Finds all users with a given gpo name on target server.
        .PARAMETER Computername
            Target computer to search the gpo of. 
        .PARAMETER GroupPolicyName
            The name you are searching for. 
        .PARAMETER Credientals
            Credientals to use on target computer
		.EXAMPLE
            
		.LINK
		    https://github.com/boldingdp/
		.NOTES
            Author: David Bolding
            Site: https://github.com/boldingdp/
	#> 
    [cmdletbinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Provide the target hostname",
            Mandatory = $true)]
        [Alias('Hostname', 'cn')][String]$Computername,
        [Parameter(
            HelpMessage = "Provide the target hostname",
            Mandatory = $true)]
        [Alias('GroupPolicy', 'GPO', 'ID')][String]$GroupPolicyName,
        [Parameter(HelpMessage = "Allows for custom credential.")][System.Management.Automation.PSCredential]$Credential
    )
    if (Test-Connection -ComputerName $Computername -Quiet -Count 1) {
        $GPO = Get-GPOName -GroupPolicyName $GroupPolicyName
        If ($null -ne $GPO) {
            $Domain = (Get-ADDomain).netbiosname
            if ($PSBoundParameters.ContainsKey('Credential')) {
                $CIMSession = New-CimSession -ComputerName $computername -Credential $Credential
                $Users = (Get-CimInstance -ClassName win32_account -CimSession $CIMSession | Where-Object { $_.domain -like "*$Domain*" }).name 
                Remove-CimSession -CimSession $CIMSession
            }
            else {
                $Users = (Get-CimInstance -ClassName win32_account -ComputerName $Computername | Where-Object { $_.domain -like "*$Domain*" }).name
            }
            foreach ($user in $Users) { }
            if ($PSBoundParameters.ContainsKey('Credential')) {
                $UsersGPOs = Get-ComputerPCGPO -Computernames $Computername -usernames $User -Credentials $Credential
            }
            else {
                $UsersGPOs = Get-ComputerPCGPO -Computernames $Computername -usernames $User 
            }
            $UsersGPOs | Where-Object { $_.name -like "$($GPO.displayname)" }
        }
    }
    else {
        Write-Warning "$GroupPolicyName does not exist."
    }
}
function Get-SHDUnlinkedGPOs {
    $gpos = Get-Gpo -All
    foreach ($gpo in $gpos) {
        [xml]$gpoReport = Get-GPOReport -Guid $gpo.ID -ReportType xml
        if (-not $gpoReport.GPO.LinksTo) {
            $gpo.DisplayName
        }
    }
}
function Get-SHDGPOLinks {
    [cmdletbinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Provide the target hostname",
            Mandatory = $true)][Alias('GPO', 'DisplayName')][String]$GPOName
    )
    $gpos = Get-Gpo -Name $GPOName 
    foreach ($gpo in $gpos) {
        [xml]$gpoReport = Get-GPOReport -Guid $gpo.ID -ReportType xml
        $gpoReport.gpo.LinksTo
    }
}
function Get-GPOUserTestResults {
    param (
        [parameter(HelpMessage = "Domain\Username", Mandatory = $True)][string]$username,
        [parameter(HelpMessage = "Target Computer Name", Mandatory = $True)][string]$Computername
    )
    $reportpath = "$($env:USERPROFILE)\Desktop\$($Username -replace '/\','_')-$Computername-GPO-Report.xml"
    Get-GPResultantSetOfPolicy -Computer $Computername -User $username -ReportType xml -Path $reportpath
    [xml]$test = Get-Content $reportpath
    $GPOs = $test.rsop.userresults.gpo
    $GPOs += $test.rsop.ComputerResults.GPO
    $GPOs
}
Function Get-SHDReceiveConnectorScope {
    [cmdletbinding()]
    param (
        [parameter(HelpMessage = "Receive Connector Idenitiy", Mandatory = $True)][string]$ReceiveConnectorIdentity,
        [switch]$Connectivity,
        [String]$DHCPInfo
    )

    if (!(Get-Command get-mailbox)) {
        import-SHDexchange
        Write-Verbose "Importing Exchange"
    }
    else {
        Write-Verbose "Exchange already present."
    }

    $Return = @()
    (Get-ReceiveConnector -Identity $ReceiveConnectorIdentity).RemoteIPRanges | ForEach-Object {
        Write-Verbose "Testing $_"
        $Tmp = $null
        if ($Connectivity) {
            $Tmp = [pscustomobject]@{
                IP           = $_
                Connectivity = Test-Connection -ComputerName $_ -Quiet -Count 1 
            }
        }
        else {
            $Tmp = [pscustomobject]@{
                IP = $_
            }
        }
        if ($PSBoundParameters.ContainsKey('DHCPInfo')) {
            try {
                $info = Get-DhcpServerv4Lease -IPAddress $_ -ComputerName $DHCPInfo
                $Tmp | Add-Member -MemberType NoteProperty -Name "Hostname" -Value $Info.Hostname
                $Tmp | Add-Member -MemberType NoteProperty -Name "MacAddress" -Value $Info.ClientID
                $Tmp | Add-Member -MemberType NoteProperty -Name "AddressState" -Value $Info.AddressState
            }
            catch {
                Write-Warning "No DHCP Info for $_"
            }
        }
        $Return += $Tmp
    }
    $Return
}

#------------------------Other--------------------

function Get-SHDWhatToEat { }
function Invoke-SHDMoveFiles {
    <#
    .SYNOPSIS
        Copy files from target source folders to a set of target folders. 
    .DESCRIPTION
        Copys from multiple source folders to a select target folders. This allows archiving to occur. 
        The folders are not auto created. Thus, the folders must exists. The script also adds a log file of any error
        messages you see. See notes for more details.
    .PARAMETER SourceFolder
        [String[]] SourceFolder is an Array of Strings of target folders to move the files from. 
    .PARAMETER TargetFolder
        [String[]] TargetFolder is an Array of strings where the files will be copied to. This is not a one for one ratio. Thus all files will exist inside the targetfolder.
    .EXAMPLE
        ./Invoke-SHDMoveFiles -SourceFolder 'C:\tbc\Tmp\Source Folder\','C:\tbc\tmp\Source Folder 2\' -TargetFolder 'C:\tbc\tmp\Target Folder\','C:\tbc\tmp\Target Folder 2\'
        Moves all files from the source folder 1 and 2 to target folders 1 and 2. 
    .EXAMPLE
        ./Invoke-SHDMoveFiles -SourceFolder 'C:\tbc\Tmp\Source Folder\' -TargetFolder 'C:\tbc\tmp\Target Folder\','C:\tbc\tmp\Target Folder 2\'
        Moves all files from the source folder 1 to target folders 1 and 2. 
    .EXAMPLE
        ./Invoke-SHDMoveFiles -SourceFolder 'C:\tbc\Tmp\Source Folder 1\','C:\tbc\Tmp\Source Folder 2\','C:\tbc\Tmp\Source Folder 3\'  -TargetFolder 'C:\tbc\tmp\Target Folder\'
        Moves all files from the source folder 1, 2, and 3 to the target folder
    .EXAMPLE
        ./Invoke-SHDMoveFiles -SourceFolder 'C:\tbc\Tmp\Source Folder\','C:\tbc\tmp\Source Folder 2\' -TargetFolder 'C:\tbc\tmp\Target Folder\','C:\tbc\tmp\Target Folder 2\' -Recurse
        Moves all files under Source folder 1 and 2 to target folders 1 and 2. 
    .EXAMPLE
        ./Invoke-SHDMoveFiles -SourceFolder 'C:\tbc\Tmp\Source Folder\' -TargetFolder 'C:\tbc\tmp\Target Folder\','C:\tbc\tmp\Target Folder 2\' -Recurse
        Moves all files under source folder 1 to target folders 1 and 2. 
    .EXAMPLE
        ./Invoke-SHDMoveFiles -SourceFolder 'C:\tbc\Tmp\Source Folder 1\','C:\tbc\Tmp\Source Folder 2\','C:\tbc\Tmp\Source Folder 3\'  -TargetFolder 'C:\tbc\tmp\Target Folder\' -Recurse
        Moves all files under source folder 1, 2, and 3 to the target folder
    .INPUTS
        [String] Folder Paths
    .OUTPUTS
        No Output
    .NOTES
        Author: David Bolding
        Date: 8/16/2020
        Purpose: Moving files around and making archives
        Min Powershell Version: 4

        This command generates error logs located c:\tbc\SHDMoveFileLog.txt. The error logs structure is broken up in 4 sections seperated with by ;
        1;$((Get-Date).tostring());Catch;$($_.Exception)
        1 - The placement of the error physically inside the script. 
        2 - The date and time of the error
        3 - What type of error
        4 - Information about the error

        Run this command inside a scheduled task every 5 minutes to copy files needed to required locations. Make sure the
        tasks running user has full access right to the file locations provided. 
    .LINK
        https://bolding.us
    #>
    [cmdletbinding()]
    param (
        [Parameter(HelpMessage = "Source Folder", Mandatory = $True)][string[]]$SourceFolder,
        [Parameter(HelpMessage = "Target Folders", Mandatory = $True)][string[]]$TargetFolder,
        [parameter(HelpMessage = "Recurse the Source Folder")][switch]$Recruse
    )
    #Tests to see if local c:\tbc exists, if it doesn't, it will create the path. 
    if (Test-Path c:\tbc) { "" >> c:\tbc\SHDMoveFileLog.txt } else { mkdir c:\tbc }

    #Start with the first source
    foreach ($Source in $SourceFolder) {

        #Tests to see if the source path exists.
        if (Test-Path -Path $Source) {

            #Grabs the required files from the first source path. It only grabs files. 
            #Also checks if there is a recruse flag. If so, recurses accordingly.
            if ($Recruse) { $files = Get-childitem -Path $Source -File -Recurse } else { $files = Get-childitem -Path $Source -File }

            #Next we sort through the files in question
            foreach ($File in $files) {

                #Create a test bool. 
                $success = $false 

                #Starts the target folder sorting
                foreach ($Target in $TargetFolder) {

                    #Tests to see if target folder exists. If not, logs. 
                    if (Test-Path -Path $target) {

                        #Enter a try catch to copy the files
                        try {

                            #Copys a single file to target folder. Overwrites any other there without confirmation
                            #No Confiramtion due to the lack of human Interaction. 
                            Copy-Item -Path $file.fullname -Destination $Target -Force -Confirm:$false

                            #If no error so far, sets the success bool to true
                            $success = $true
                        }
                        catch {

                            #a failure occured, thus we set the success bool to false
                            $success = $false 

                            #We log the error. This is the first log that shows up in the system. 
                            #We date it.
                            #We state it's a catch
                            #Then we give the reason the try catch gives. 
                            write-warning "Could not Copy $($file.FullName)"
                            #"1;$((Get-Date).tostring());Catch;$($_.Exception)" >> c:\tbc\SHDMoveFileLog.txt
                        }
                    }
                    else {
                        #We log the fact that we can't reach the target location
                        Write-Warning "Can Not Find $Target"
                        #"2;$((Get-Date).tostring());CanNotFind;$Target" >> c:\tbc\SHDMoveFileLog.txt
                    }
                }
                #We test the bool for success.
                if ($success -eq $true) {
                    try {

                        #if successful we remove the file.
                        Remove-Item -Path $file.FullName -Force -Confirm:$false 
                    }
                    catch {

                        #If we can't remove the file we log the reason why. 
                        Write-Warning "Could not remove $($file.FullName)"
                        #"3;$((Get-Date).tostring());Catch;$($_.Exception)" >> c:\tbc\SHDMoveFileLog.txt
                    }
                } 
            }
        }
        else {
            #We log the fact we can't reach the source location.
            Write-Warning "Could not find $Source"
            #"4;$((Get-Date).tostring());CanNotFind;$Source" >> c:\tbc\SHDMoveFileLog.txt
        }
    }
}          
function Get-SHDRemainingHours {
    [cmdletbinding()]
    param (
        [parameter(HelpMessage = "The Decimel Point value of hours worked this week", Mandatory = $True)][decimal]$Time,
        [parameter(HelpMessage = "Start date of the day.", Mandatory = $True)][DateTime]$StartTime
    )
    $Minus40 = "$(40 - [decimal]$Time)"
    [decimal]$PointMinutes = ".$($Minus40.Split('.')[1])"
    $Minutes = [math]::Round($PointMinutes * 60)
    $Hour = $Minus40.Split('.')[0]
    $TimeRemaining = "$($Hour):$($Minutes)"
    if ($PSBoundParameters.ContainsKey("StartTime")) {
        $LeavingTime = ([datetime]$StartTime).AddHours($Hour).AddMinutes($Minutes)
    }
    else {
        $LeavingTime = (Get-Date).AddHours($Hour).AddMinutes($Minutes)
    }
    [pscustomobject]@{
        Hours         = $Hour
        Minutes       = $Minutes
        TimeRemaining = $TimeRemaining
        LeavingTime   = $LeavingTime
    }
}
Function Invoke-SHDBallonTip {
    [cmdletbinding()]
    param (
        [string]$Message = "Your task is finished",
        [int]$Time = 10000,
        [validateset("Info", "Warning", "Error")][string]$Messagetype = "Info"
    )
    Add-Type -AssemblyName System.Windows.Forms 
    $global:balloon = New-Object System.Windows.Forms.NotifyIcon
    $path = (Get-Process -id $pid).Path
    $balloon.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path) 
    $balloon.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::$Messagetype
    $balloon.BalloonTipText = $Message
    $balloon.BalloonTipTitle = "Attention" 
    $balloon.Visible = $true 
    $balloon.ShowBalloonTip($Time)
}
Function Convert-SHDArraytoLineofText {
    [cmdletbinding()]
    param (
        [parameter(HelpMessage = "Input of Array", Mandatory = $true)][array]$TheArray
    )
    $Line = ""
    $TheArray = $TheArray | Sort-Object
    foreach ($Info in $TheArray) {
        $Line += """$Info"","
    }
    $Line = $Line.Substring(0, $Line.Length - 1)
    $Line | Clip
    Write-Host "Input is on in your clipboard: $Line"
}
Function Get-SHDBingImage {
    [cmdletbinding()]
    param (
        [string]$Search = "Super Help Desk",
        [string]$FileLocation = "$($Env:USERPROFILE)\Pictures",
        [switch]$Save
    )
    $Search = $Search -replace (' ', '+')
    $URL = "https://www.bing.com/images/search?&q=$Search&qft=+filterui:aspect-wide+filterui:imagesize-custom_1920_1080&FORM=IRFLTR"
    $Webrequest = Invoke-WebRequest -Uri $URL -UseBasicParsing -DisableKeepAlive
    $ImgURL = $Webrequest.Images.src | Where-Object { $_ -like "https*" } | Get-random -Count 1 -ov ImageURL
    if ($Save) {
        Invoke-WebRequest -Uri $ImgURL -OutFile "$FileLocation\$Search.jpg"
    }
    else {
        $ImgURL | clip
    }
}
function Get-SHDOpenFiles {
    [cmdletbinding()]
    param (
        [parameter(Helpmessage = "Computer Name", Mandatory = $True)][alais('Computer', 'PCName')][string[]]$ComputerName
    )
    foreach ($Computer in $ComputerName) {
        if (Test-Connection -ComputerName $Computer -Quiet -Count 1) {
            try {
                openfiles.exe /query /s $Computer /v /fo csv | ConvertFrom-Csv
            }
            catch {
                Write-Warning "-----------Failed to capture files on $Computer. Error message-----------"
                Write-Warning $_.Exception
            }
        }
        else {
            write-warning "$Computer is offline."
        }
    }
}
function Get-SHDUrlStatusCode {
    [cmdletbinding()]
    param (
        [parameter(HelpMessage = "Website you are wanting to test.", Mandatory = $True)][alias('Website')][string]$Url
    )  
    try {
        (Invoke-WebRequest -Uri $Url -UseBasicParsing -DisableKeepAlive -Method Head).StatusCode
    }
    catch [Net.WebException] {
        [int]$_.Exception.Response.StatusCode
    }
}
Function Resolve-SHDIP {
    [cmdletbinding()]
    param (
        [parameter(HelpMessage = "IP Address you wish to resolve.", Mandatory = $True)][alias('IP')][ipaddress]$IPaddress
    )
    try {
        [System.Net.Dns]::gethostentry($IPaddress)
    }
    Catch {
        Write-Host "DNS does not have $IPaddress."
    }
}
function Invoke-SHDqoutes {
    [cmdletbinding()]
    param (
        [string]$line,
        [string]$Delimiter = ',',
        [string]$NewDelimiter = ','
    )
    Begin {
        $Return = ""
    }
    Process {
        $Temps = $line.Split("$Delimiter")
        foreach ($temp in $Temps) {
            $return += '"' + $temp + '"' + "$NewDelimiter"       
        } 
    }
    End {
        $return.Trim("$NewDelimiter") | clip
    }
}

