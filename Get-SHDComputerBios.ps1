function Get-SHDComputerBios {
    [cmdletbinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Provide the target hostname",
            Mandatory = $true)][Alias('Hostname', 'cn')][String[]]$Computername,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )$parameters = @{
        ComputerName = $ComputerName
        ScriptBlock  = {
            try {
                Get-CimInstance -ClassName win32_bios
            } Catch {
                try {
                    get-wmiobject -class win32_bios
                } catch {
                    Write-Warning "Failed to capture bios info from $($env:COMPUTERNAME)"
                }
            }
        }
    }
    if ($PSBoundParameters.ContainsKey('Credential')) { $parameters += @{Credential = $Credential } }
    Invoke-Command @parameters | sort-object pscomputername | Select-Object pscomputername, name, manufacturer, SMBIOSBIOSVersion, Version, serialnumber
} #review - Order,testing,Documentation