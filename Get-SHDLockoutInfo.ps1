Function Get-SHDLockoutInfo {
    [cmdletbinding()]
    param (
        [parameter(Helpmessage = "Username of target")][Alias('User', 'Samaccountname')][String[]]$Username,    
        [parameter(Helpmessage = "Days back")][int]$Day,
        [parameter(Helpmessage = "Days back")][int]$Hour,
        [parameter(Helpmessage = "Days back")][int]$Minute,
        [parameter(Helpmessage = "Computers to target, default is domain controllers.")][Alias('Computer', 'PC')][String[]]$ComputerName = (Get-ADDomain).ReplicaDirectoryServers,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )
    $time = Get-date
    if ($PSBoundParameters.ContainsKey('Day')) { $time = ($time.AddDays( - ($day))) } 
    if ($PSBoundParameters.ContainsKey('Hour')) { $time = ($time.AddHours( - ($Hour))) } 
    if ($PSBoundParameters.ContainsKey('Minute')) { $time = ($time.AddMinutes( - ($Minute))) } 
    if (!($PSBoundParameters.ContainsKey('Day')) -and !($PSBoundParameters.ContainsKey('Hour')) -and !($PSBoundParameters.ContainsKey('Minute'))) {
        $time = $time.AddDays( - (1))
    }
    $parameters = @{
        ComputerName = $ComputerName
        ScriptBlock  = {
            Param ($param1)
            $FilterTable = @{
                'StartTime' = $param1
                'EndTime'   = (Get-date)
                'LogName'   = 'Security'
                'Id'        = 4740
            }
            $Events = Get-WinEvent -FilterHashtable $FilterTable
            foreach ($E in $Events) {
                [pscustomobject]@{
                    Time     = $E.TimeCreated
                    ID       = $E.ID 
                    DC       = $E.Properties[4].value
                    SID      = $E.Properties[2].value
                    Domain   = $E.Properties[5].Value
                    Username = $E.Properties[0].value
                    Computer = $E.Properties[1].value
                }
            }
        }
        ArgumentList = $time           
    }
    if ($PSBoundParameters.ContainsKey('Credential')) {
        $parameters += @{Credential = $Credential }
    }
    $Return = Invoke-Command @parameters 
    if ($PSBoundParameters.ContainsKey('Username')) {
        foreach ($user in $Username) {
            $Return | Where-Object { $_.Username -like "$user" } | Sort-Object Time | Select-Object Username, Domain, SID, Time, Computer, PSComputerName
        }
    }
    else {
        $Return | Sort-Object UserName | Select-Object Username, Domain, SID, Time, Computer, PSComputerName
    }
} #Review - Testing, Documentation

#Flow state