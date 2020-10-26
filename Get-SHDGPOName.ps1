function Get-SHDGPOName {
    <#
		.SYNOPSIS
		    Finds a group policy by a name given.
		.DESCRIPTION
		    If you can't remember a group policy's full name, yo ucan find it with this script.
        .PARAMETER GroupPolicyName
            The name you are searching for.
		.EXAMPLE
            Get-GPOName -GroupPolicyName "Firewall"

            Finds the group policy with the matching name.

            DisplayName      : Domain Firewall
            DomainName       : Domain
            Owner            : User
            Id               : 00000000-0000-0000-0000-000000000000
            GpoStatus        : AllSettingsEnabled
            Description      :
            CreationTime     : 7/9/2003 11:03:33 AM
            ModificationTime : 7/9/2003 12:55:20 PM
            UserVersion      :
            ComputerVersion  :
            WmiFilter        :
		.LINK
		    https://github.com/rndadhdman/PS_Super_Helpdesk
		.NOTES
            Author: David Bolding
            Site: https://github.com/rndadhdman/PS_Super_Helpdesk
	#>
    [CmdletBinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Provide the target hostname",
            Mandatory = $true)]
        [Alias('GroupPolicy', 'GPO', 'ID')][String]$GroupPolicyName
    )
    $AllGPOs = Get-GPO -All
    $AllGPOs | Where-Object { $_.DisplayName -like "*$GroupPolicyName*" }
}