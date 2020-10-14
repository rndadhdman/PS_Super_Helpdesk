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
    $parameters = @{
        ComputerName = $ComputerName
        ScriptBlock  = {
            Get-CimInstance -Class win32_battery | Select-Object pscomputername, Name, Caption, status, EstimatedRunTime, EstimatedChargeRemaining, DesignVoltage
        }
    }
    if ($PSBoundParameters.ContainsKey('Credential')) { $parameters += @{Credential = $Credential } }
    Invoke-Command @parameters | Select-Object pscomputername, Name, Caption, status, EstimatedRunTime, EstimatedChargeRemaining, DesignVoltage
} #Review - Documentation