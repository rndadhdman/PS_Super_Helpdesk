Function Copy-SHDUserGroupToUser {
    <#
    .SYNOPSIS
        Copys target users groups to a set of users. 
    .DESCRIPTION
        This commandlet copy's a target users groups to another user or a set of users. 
        You can choose all group, security groups, distribution groups, domain, global and universal groups to copy. 
        You can chose to use your currently running credentials or a different set of credentials.
        It doesn't matter how many target users you have, it will loop through each one granting the groups. 
    .PARAMETER SourceUser
        A mandatory parameter that can be piped in that give the target username. This will be the user that you will grab all the group information from. 
    .PARAMETER Targetuser
        A mandatory list of strings. Targetuser is the usernames of each target you wish to deploy the sourceuser's groups to.
    .PARAMETER GroupCategory
        A validated set between Security and Distribution groups. By using this, you are adding the sourceuser's security or distrubtion groups to the target user. 
        If you do not use this flag, you will add all the other groups accordingly to the targetuser.
    .PARAMETER GroupScope
        A validated set between Universal, global, or domainlocal groups. By using this you are adding the sourceuser's Universal, global or domainlocal groups to the target user.
        If you do not use this flag, you will add all the other groups accordingly to the targetuser.
    .PARAMETER Credential
        Optional Credentials to run the command with
    .PARAMETER RemoveGroups
        A switch parameter that will remove the previous groups. if the Groupcategory or group scope is set, those groups accordingly will be removed. 
    .EXAMPLE
        Copy-SHDUserGroupToUser -SourceUser Bob -TargetUser Frank,Tim,Yugi

        In this example, all of bob's groups will be copied to Frank, Tim and Yugi. Frank, Tim and Yugi will also have whatever groups they had before hand.
    .EXAMPLE
        Copy-SHDUserGroupToUser -SourceUser Bob -TargetUser Frank,Tim,Yugi -GroupCategory Security

        In this example all of bob's security groups will be copied to Frank, Tim, and Yugi. Frank, Tim and Yugi will also have whatever groups they had before hand. 
    .EXAMPLE
        Copy-SHDUserGroupToUser -SourceUser Bob -TargetUser Frank, Tim -GroupScope DomainLocal

        In this example, all of bob's domain local groups will be copied to frank and Tim. Frank and Tim will also have whatever groups they had before hand. 
    .EXAMPLE
        Copy-SHDUserGroupToUser -SourceUser Bob -TargetUser Frank,Tim -GroupCategory Security -RemoveGroups

        In this example, Frank and Tim's security groups will be removed. Bob's securtiy groups will then be added to Frank and Time. Distribution groups will not be touched. 
    .EXAMPLE
        Copy-SHDUserGroupToUser -SourceUser Bob -TargetUser Frank,Tim -GroupScope Universal -GroupCategory Distribution -RemoveGroups -Credential (Get-Credential)

        In this example, we will remove all of Frank and Tim's Universal Distribution groups and add bob's universal distrubtion groups. 
        The command will do this using credentials provided by the user. 
    .INPUTS 
        Username
    .OUTPUTS
        none
    .NOTES
        author: David Paul Bolding
        date: 10/12/2020


    .LINK
        https://github.com/rndadhdman/PS_Super_Helpdesk
    #>
    [cmdletbinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Enter a users Name",
            Mandatory = $true)][String]$SourceUser,
        [Parameter(HelpMessage = "Target User", Mandatory = $True)][string[]]$TargetUser,
        [parameter(Helpmessage = "Group Category")][validateset("Security", "Distribution")]$GroupCategory,
        [parameter(Helpmessage = "Group Scope")][validateset("Universal", "Global", "DomainLocal")]$GroupScope,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential,
        [parameter(helpmessage = "Removes All Groups")][switch]$RemoveGroups
    )
    $Groups = (Get-ADUser -Identity $SourceUser -Properties memberof).memberof -Replace '^cn=([^,]+).+$', '$1' | Sort-Object | ForEach-Object { (Get-ADGroup -Filter "name -like '$_'") }
    if ($PSBoundParameters.ContainsKey('GroupCategory')) { $Groups = $Groups | Where-Object { $_.GroupCategory -like "$GroupCategory" } }
    if ($PSBoundParameters.ContainsKey('GroupScope')) { $Groups = $Groups | Where-Object { $_.GroupScope -like "$GroupScope" } }
    foreach ($Target in $TargetUser) {
        if ($RemoveGroups) {
            $TGroups = (Get-ADUser -Identity $Target -Properties memberof).memberof -Replace '^cn=([^,]+).+$', '$1' | Sort-Object | ForEach-Object { (Get-ADGroup -Filter "name -like '$_'") }
            if ($PSBoundParameters.ContainsKey('GroupCategory')) { $TGroups = $TGroups | Where-Object { $_.GroupCategory -like "$GroupCategory" } }
            if ($PSBoundParameters.ContainsKey('GroupScope')) { $TGroups = $TGroups | Where-Object { $_.GroupScope -like "$GroupScope" } }
            $TGroups | ForEach-Object {
                try {
                    if ($PSBoundParameters.ContainsKey('Credential')) {
                        Write-Verbose "Remove $($_.Samaccountname) a $($_.GroupCategory.tostring()) a $($_.GroupScope.tostring()) to $Target"
                        Remove-ADGroupMember -Identity $_.samaccountname -Members $Target -Credential $Credential -Confirm:$false
                    }
                    else {
                        Write-Verbose "Remove $($_.Samaccountname) a $($_.GroupCategory.tostring()) a $($_.GroupScope.tostring()) to $Target"
                        Remove-ADGroupMember -Identity $_.samaccountname -Members $Target -Confirm:$false
                    }
                }
                catch {
                    Write-Verbose "Failed to Remove $($_.Samaccountname) to $Target"
                    Write-Warning "$($_.samaccountname) could not apply to $Target"
                }
            }
        }
        $Groups | ForEach-Object {
            try {
                if ($PSBoundParameters.ContainsKey('Credential')) {
                    Write-Verbose "Add $($_.Samaccountname) a $($_.GroupCategory.tostring()) a $($_.GroupScope.tostring()) to $Target"
                    Add-ADGroupMember -Identity $_.samaccountname -Members $Target -Credential $Credential
                }
                else {
                    Write-Verbose "Add $($_.Samaccountname) a $($_.GroupCategory.tostring()) a $($_.GroupScope.tostring()) to $Target"
                    Add-ADGroupMember -Identity $_.samaccountname -Members $Target
                }
            }
            catch {
                Write-Verbose "Failed to add $($_.Samaccountname) to $Target"
                Write-Warning "$($_.samaccountname) could not apply to $Target"
            }
        }
    }
}