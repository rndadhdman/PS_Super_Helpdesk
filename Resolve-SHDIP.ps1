Function Resolve-SHDIP {
    <#
    .SYNOPSIS
        Resolves the DNS name of target IP address.
    .DESCRIPTION
        Resolves the DNS name of target IP address.
    .PARAMETER IPaddress
        Target IP address
    .EXAMPLE
        PS C:\Users\dbolding_adm> Resolve-SHDIP -IPaddress 10.10.10.11
        HostName             Aliases AddressList
        --------             ------- -----------
        Server1.example.com  {}      {10.10.10.11}
    .INPUTS
        ipaddress
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
        [parameter(HelpMessage = "IP Address you wish to resolve.", Mandatory = $True)][alias('IP')][ipaddress]$IPaddress
    )
    try {
        [System.Net.Dns]::gethostentry($IPaddress)
    }
    Catch {
        Write-Host "DNS does not have $IPaddress."
    }
}