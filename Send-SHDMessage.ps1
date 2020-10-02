function Send-SHDMessage {
    <#
    .SYNOPSIS
        Sends a decently formated email message to a list of users from a supplied user. 
    .DESCRIPTION
        Sends a decently formated email message to a list of users from a supplied user. 
    .PARAMETER Users
        Mandatory: This is where you can put the multiple usernames of each person you wish to email.
    .PARAMETER Message
        Mandatory: This is a string that will be used as the message. Please note, you do not need to add a dear or a thank you. 
    .PARAMETER SenderEmail
        Mandatory: This will be the senders email address. When a person replys to the email, they will reply to this email address. 
    .PARAMETER SenderName
        Mandatory: The name which you will use on the sender email. This can be a different name to make it look like you are sending on behalf of someone. 
    .PARAMETER Subject
        Mandatory: THe subject of the email.
    .PARAMETER MailServer
        Mandatory: The mail server you are going to use. 
    .PARAMETER Credential
        Optional credentials switch that allows you to use another credential.
    .EXAMPLE
        $Message = @{
            Username = "bsmith","nanderson","mjohnson"
            Message = "We regrat to inform you, you were given another raise of 20%.<p> Please dance quietly as not to distrub cookie from eating her cookies.</p>"
            SenderEmail = "HR@example.com"
            SenderName = "Bob Jackson"
            Subject = "Raze Party"
            MailServer = Mail.example.com
            Credential = (get-credential)
        }
        Send-SHDMessage @Message
    .OUTPUTS
        [none]
    .NOTES
        Author: David Bolding

    .LINK
        https://github.com/rndadhdman/PS_Super_Helpdesk
    #>
    [cmdletbinding()]
    param (
        [Parameter(HelpMessage = "Allows for custom Credential.", Mandatory = $True)][string[]]$username,
        [Parameter(HelpMessage = "The Message to send.", Mandatory = $True)][String]$Message,
        [Parameter(HelpMessage = "The Reply email.", Mandatory = $True)][String]$SenderEmail,
        [Parameter(HelpMessage = "The Name of the sender.", Mandatory = $True)][string]$Sendername,
        [Parameter(HelpMessage = "Message subject.", Mandatory = $True)][String]$Subject,
        [Parameter(HelpMessage = "Mail Server.", Mandatory = $True)][string]$MailServer,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )

    Write-Verbose "Starting User Loop to Send email."
    foreach ($user in $username) {

        Write-Verbose "Getting user Information"
        try {
            $TheUser = Get-ADUser -Identity $user -Properties *
        }
        catch {
            Write-Warning "$User can not be found."
            break
        }
        
        if ($TheUser.Enabled -eq $true) {

            Write-Verbose "Building the HTML part of the email."
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
            Write-Verbose "Sending the email to $($TheUser.Mail) from $($SenderMail)"
            if ($PSBoundParameters.ContainsKey('Credential')) {
                Send-MailMessage -To $TheUser.mail -From "$Sendername <$SenderEmail>" -Subject "$Subject" -BodyAsHtml $htmlbody -SmtpServer $MailServer -Credential $Credential
            }
            else {
                Send-MailMessage -To $TheUser.mail -From "$Sendername <$SenderEmail>" -Subject "$Subject" -BodyAsHtml $htmlbody -SmtpServer $MailServer
            }
        }
        else {

            Write-Verbose "Displays the disabled username"
            $TheUser | Select-Object Name, Samaccountname, Enabled
        }
    }
} #Review - Testing, Documentation

