function Set-SHDProfilePicture {
    <#
    .SYNOPSIS
        This script is designed to set a users profile picture.
    .DESCRIPTION
        This script is designed to set a users profile picture based on a file image path that you provide.
    .PARAMETER EmailAddress
        The Email address you wish to target
    .PARAMETER ImagePath
        The full name of the image you wish to use.
    .EXAMPLE
        Set-SHDProfilePicture -Emailaddress Bob@Example.com -ImagePath c:\Images\Bob.jpg
    .INPUTS
        None
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
        [Parameter(Mandatory = $true)][string]$EmailAddress,
        [Parameter(Mandatory = $true)][string]$ImagePath
    )

    #Tests if you are connected to
    if (!(Get-Command get-mailbox)) {
        import-SHDexchange -Servername (Read-Host "Exchange Server Name to Connect to") -Credential (get-credential)
        Write-Verbose "Importing Exchange"
    }
    else {
        Write-Verbose "Exchange already present."
    }

    if (!(Get-Mailbox -Identity $EmailAddress)) {
        Write-Host "$EmailAddress mailbox is closed."
        break
    }
    else {
        Write-Verbose "$($EmailAddress)'s Mailbox Present."
    }
    #$username = "dbolding"
    if (Test-Path $ImagePath) {
        $Photo = Get-ChildItem "$ImagePath"
        Write-Verbose "$($EmailAddress)'s photo exists."
    }
    else {
        Write-Host "$($EmailAddress)'s photo is not present."
        break
    }

    #trys to set the user's photo
    try {
        Remove-UserPhoto -Identity "$EmailAddress" -Confirm:$false
        Set-UserPhoto -Identity "$EmailAddress" -PictureData ([System.IO.File]::ReadAllBytes($Photo.FullName)) -Confirm:$false
        Set-CASMailbox "$EmailAddress" -OwaMailboxPolicy default
        Write-Verbose "$($EmailAddress)'s photo set."
    }
    catch {
        Write-Host "$EmailAddress failed to load photo."
        break
    }

    #displays the user's photo information.
    Get-UserPhoto -Identity "$EmailAddress"
}
