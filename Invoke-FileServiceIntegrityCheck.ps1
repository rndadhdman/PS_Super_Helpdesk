function Invoke-FileServiceIntegrityCheck {
    <#
    .SYNOPSIS
        Checks a file path for number of files. If greater, restarts a service and emails a message and logs a log.
    .DESCRIPTION
        Checks a file path for a set number of files that are predefined by the end user. If the file count is greater, it will restart a service. It will log the results and email a person stated by the end user.
    .PARAMETER SearchPath
        Target Path to scan for file count.
    .PARAMETER FileCount
        File count that will be used to determine the request size.
    .PARAMETER ComputerName
        Target Computer Name that the service lives on.
    .PARAMETER ServiceName
        Name of the service to restart.
    .PARAMETER SendReportTo
        The email address to which the email report will be sent to.
    .PARAMETER EmailDomain
        The domain name. For example, example.local
    .PARAMETER MailServer
        The mail server to send the email from.
    .PARAMETER Recurse
        Recurses the file search path.
    .PARAMETER Credential
        The Credentials, if needed for the email server.
    .EXAMPLE
        Invoke-FileServiceIntegrityCheck -SearchPath \\server1\share -FileCount 25 -ComputerName server2 -ServiceName intergrator -SendReportTo bob@example.com -EmailDomain example.com -Mailserver mail.example.com -Credential (Get-Credential)

        Checks the folder \\server1\share to see if there is 25 or more files. If it does, it will restart the service named intergrator on server 2.
        Then it will send an bob@example.com from watcheye@example.com using mail.example.com and the credentials provided.
    .EXAMPLE
        Invoke-FileServiceIntegrityCheck -SearchPath \\server1\share -FileCount 25 -ComputerName server2 -ServiceName intergrator -SendReportTo bob@example.com -EmailDomain example.com -Mailserver mail.example.com

        Checks the folder \\server1\share to see if there is 25 or more files. If it does, it will restart the service named intergrator on server 2.
        Then it will send an bob@example.com from watcheye@example.com using mail.example.com. Email will be sent from the server. If no relay is setup, the server will reject the email.
    .INPUTS
        [none]
    .OUTPUTS
        email and log
    .NOTES
        Author: David Bolding
        Date: 10/14/2020

    .LINK
        https://github.com/rndadhdman/PS_Super_Helpdesk
    #>
    [cmdletbinding()]
    param (
        [parameter(HelpMessage = "Folder Search Path", Mandatory = $True)][string]$SearchPath,
        [parameter(HelpMessage = "File Count", Mandatory = $True)][int]$FileCount,
        [parameter(HelpMessage = "Computer That the server Lives", Mandatory = $True)][String]$ComputerName,
        [parameter(HelpMessage = "Service Name", Mandatory = $True)][String]$ServiceName,
        [parameter(HelpMessage = "Service Name", Mandatory = $True)][String]$SendReportTo,
        [parameter(HelpMessage = "Service Name", Mandatory = $True)][String]$EmailDomain,
        [parameter(HelpMessage = "Service Name", Mandatory = $True)][String]$Mailserver,
        [parameter(HelpMessage = "Recurse the Search")][switch]$Recurse
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )

    #Checks Files
    if ($Recurse) { $Files = Get-ChildItem "$SearchPath" -Recurse } else { $Files = Get-ChildItem "$SearchPath" }


    if ($Files.Count -ge $FileCount) {

        $StopTime = Get-date
        Get-Service -ComputerName mtxs-lifetecapp -Name "ITSy_bexWISE_Interlink" | Stop-Service

        sleep 30

        Get-Service -ComputerName mtxs-lifetecapp -Name "ITSy_bexWISE_Interlink" | Start-Service
        $StartTime = Get-date

        sleep 30

        if ($Recurse) { $Files2 = Get-ChildItem "$SearchPath" -Recurse } else { $Files2 = Get-ChildItem "$SearchPath" }

        if (!(Test-Path c:\logs)) {mkdir c:\logs}

        #Gathers Log Info
        $Log = [pscustomobject]@{
            ComputerName = $ComputerName
            ServiceName = $ServiceName
            SearchPath = $SearchPath
            StopFileCount = $Files.count
            ServiceStopTime = $StopTime.ToString()
            ServiceStartTime = $StartTime.tostring()
            StartFileCount = $Files2.count
            CallingComputer = $env:COMPUTERNAME
        }

        $Log | Export-csv c:\tbc\Invoke_FileServiceIntegrityCheck_log.csv -Append

        #Builds EMail
        $ErrorHtmlbody = @"
<html>
<head>
<style>
body {
    Color: #252525;
    font-family: Verdana,Arial;
    font-size:11pt;
}
h1 {
    text-align: center;
    color:#C8102E;
    Font-size: 34pt;
    font-family: Verdana, Arial;
}
</style>
</head>
<body>
<h1>$ServiceName Restarted</h1>
<hr>
<br>
Dear Watcher,<br>
<br>
During my last check there were <b>$($Files.Count)</b> files inside <i>$SearchPath</i>. The Integrator was stopped on <b>$($StopTime.tostring())</b> and started on <b>$($StartTime.tostring())</b>. There are now <b>$($files2.count)</b> in <i>$SearchPath</i>. Please investigate on why the $ServiceName failed on $ComputerName.<br>
<br>
<br>
Thank you,<br>
<i>$ServiceName WatchEye</i><br>
<br>
<hr>
</body>
</html>
"@
        if ($PSBoundParameters.ContainsKey('Credential')) {
            Send-MailMessage -To $SendReportTo -From "Service Watch Eye <WatchEye@$EmailDomain>" -Subject "$ServiceName Failure" -BodyAsHtml $ErrorHtmlbody -SmtpServer $Mailserver -Credential $Credential
        } else {
            Send-MailMessage -To $SendReportTo -From "Service Watch Eye <WatchEye@$EmailDomain>" -Subject "$ServiceName Failure" -BodyAsHtml $ErrorHtmlbody -SmtpServer $Mailserver
        }
    }

}
