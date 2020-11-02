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
		    https://github.com/rndadhdman/PS_Super_Helpdesk
		.NOTES
            Author: David Bolding
            Site: https://github.com/rndadhdman/PS_Super_Helpdesk
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