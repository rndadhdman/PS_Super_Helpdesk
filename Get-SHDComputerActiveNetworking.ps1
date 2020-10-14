function Get-SHDComputerActiveNetworking {
    <#
    .SYNOPSIS
        Grabs active networking on target computer.
    .DESCRIPTION
        Grabs active networking on target computer. 
    .PARAMETER Computername
        [String[]] - Target computer names
    .PARAMETER Credential
        Optional credentials switch that allows you to use another credential.
    .EXAMPLE
        Get-SHDComputerActiveNetworking -ComputerName <computer1> -Credential (Get-Credential)

        Grabs the active networking from target computer using the supplied credentials
    .EXAMPLE
        Get-SHDComputerActiveNetworking -ComputerName <computer1> -Credential (Get-Credential)

        Grabs the active networking from target computer using current Credentials
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
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )
    $parameters = @{
        ComputerName = $ComputerName
        ScriptBlock  = {
            $networkConfig = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
            $ComputerNetwork = Get-CimInstance -Class win32_networkadapter
            foreach ($Net in $networkConfig) {
                $CNet = $ComputerNetwork | Where-Object { $_.MACAddress -like $net.MACAddress }
                [pscustomobject]@{
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
    }
    if ($PSBoundParameters.ContainsKey('Credential')) { $parameters += @{Credential = $Credential } }
    Invoke-Command @parameters | Select-Object PSComputerName, ConnectionName, ConnectionID, MacAddress, Subnet, DefaultGateway, DNSDomain, PrimaryDNS, SecondaryDNS, DHCPEnabled, DHCPServer, DHCPLeaseExpires
} #Review - Testing, Documentation