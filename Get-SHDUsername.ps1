function Get-SHDUsername {
    <#
    .SYNOPSIS
        Finds the username by multiple means.
    .DESCRIPTION
        Finds the username by mulitple means. It first looks for the name, givenname, surname, SID, DistinguishedName, Samaccountname, ObjectGUID, EmployeeID, EmployeeNumber, Office, email address, department, and finally the city.
    .PARAMETER Idenity
        The Name of the user you are looking for.
    .EXAMPLE
        PS C:\Users\dbolding_adm> Get-SHDUsername -Idenity "David"

        bdavidson
        david
        DavidTest
        DavidTest2
    .INPUTS
        List of strings
    .OUTPUTS
        username
    .NOTES
        Author: David Bolding
        Date: 10/15/2020
    .LINK
        https://github.com/rndadhdman/PS_Super_Helpdesk
    #>
    [cmdletbinding()]
    param (
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Enter a users Name",
            Mandatory = $true)][Alias('Username', 'Name')][String[]]$Idenity,
        [Parameter(HelpMessage = "Allows for custom Credential.")][System.Management.Automation.PSCredential]$Credential
    )
    if ($PSBoundParameters.ContainsKey('Credential')) {
        if ($null -eq $Name) {
            Write-Verbose "Testing Name"
            try {
                $Name = (Get-ADUser -Filter "name -like '*$Idenity*'" -Properties Samaccountname -Credential $Credential).samaccountname | Sort-Object
            }
            catch {
                $Name = $null
            }
            if ($null -eq $Name) { Write-Verbose "Failed Name" }
        }
        if ($null -eq $Name) {
            Write-Verbose "Testing GivenName"
            try {
                $Name = (Get-ADUser -Filter "GivenName -like '$Idenity'" -Properties Samaccountname -Credential $Credential).samaccountname | Sort-Object
            }
            catch {
                $Name = $null
            }
            if ($null -eq $Name) { Write-Verbose "Failed GivenName" }
        }
        if ($null -eq $Name) {
            Write-Verbose "Testing Surname"
            try {
                $Name = (Get-ADUser -Filter "Surname -like '$Idenity'" -Properties Samaccountname -Credential $Credential).samaccountname | Sort-Object
            }
            catch {
                $Name = $null
            }
            if ($null -eq $Name) { Write-Verbose "Failed Surname" }
        }
        if ($null -eq $Name) {
            Write-Verbose "Testing SID"
            try {
                $Name = (Get-ADUser -Filter "SID -like '$Idenity'" -Properties Samaccountname -Credential $Credential).samaccountname | Sort-Object
            }
            catch {
                $Name = $null
            }
            if ($null -eq $Name) { Write-Verbose "Failed SID" }
        }
        if ($null -eq $Name) {
            Write-Verbose "Testing DistinguishedName"
            try {
                $Name = (Get-ADUser -Filter "DistinguishedName -like '*$Idenity*'" -Properties Samaccountname -Credential $Credential).samaccountname | Sort-Object
            }
            catch {
                $Name = $null
            }
            if ($null -eq $Name) { Write-Verbose "Failed Distinguishedname" }
        }
        if ($null -eq $Name) {
            Write-Verbose "Testing Samaccountname"
            try {
                $Name = (Get-ADUser -Filter "SamAccountName -like '*$Idenity*'" -Properties Samaccountname -Credential $Credential).samaccountname | Sort-Object
            }
            catch {
                $Name = $null
            }
            if ($null -eq $Name) { Write-Verbose "Failed Samaccountname" }
        }
        if ($null -eq $Name) {
            Write-Verbose "Testing ObjectGUID"
            try {
                $Name = (Get-ADUser -Filter "ObjectGUID -like '*$Idenity*'" -Properties Samaccountname -Credential $Credential).samaccountname | Sort-Object

            }
            catch {

                $Name = $null
            }
            if ($null -eq $Name) { Write-Verbose "Failed ObjectGUID" }
        }
        $AllUsers = Get-ADUser -Filter * -Properties Samaccountname, EmployeeID, EmployeeNumber, Office, Mail, Department, City -Credential $Credential
        if ($null -eq $Name) {
            Write-Verbose "Testing EmployeeID"
            try {
                $Name = ($AllUsers | Where-Object { $_.EmployeeID -like "*$Idenity*" }).samaccountname | Sort-Object
            }
            catch {
                $Name = $null
            }
            if ($null -eq $Name) { Write-Verbose "Failed EmployeeID" }
        }
        if ($null -eq $Name) {
            Write-Verbose "Testing EmployeeNumber"
            try {
                $Name = ($AllUsers | Where-Object { $_.EmployeeNumber -like "*$Idenity*" }).samaccountname | Sort-Object
            }
            catch {
                $Name = $null
            }
            if ($null -eq $Name) { Write-Verbose "Failed EmployeeNumber" }
        }
        if ($null -eq $Name) {
            Write-Verbose "Testing Office"
            try {
                $Name = ($AllUsers | Where-Object { $_.Office -like "*$Idenity*" }).samaccountname | Sort-Object
            }
            catch {
                $Name = $null
            }
            if ($null -eq $Name) { Write-Verbose "Failed Office" }
        }
        if ($null -eq $Name) {
            Write-Verbose "Testing Email Address"
            try {
                $Name = ($AllUsers | Where-Object { $_.EmailAddress -like "*$Idenity*" }).samaccountname | Sort-Object

            }
            catch {
                $Name = $null
            }
            if ($null -eq $Name) { Write-Verbose "Failed EmailAddress" }
        }
        if ($null -eq $Name) {
            Write-Verbose "Testing Department"
            try {
                $Name = ($AllUsers | Where-Object { $_.Department -like "*$Idenity*" }).samaccountname | Sort-Object
            }
            catch {
                $Name = $null
            }
            if ($null -eq $Name) { Write-Verbose "Failed Department" }
        }
        if ($null -eq $Name) {
            Write-Verbose "Testing City"
            try {
                $Name = ($AllUsers | Where-Object { $_.City -like "*$Idenity*" }).samaccountname | Sort-Object
            }
            catch {

                $Name = $null
            }
            if ($null -eq $Name) { Write-Verbose "You failed this city" }
        }
        if ($null -eq $Name) {
            write-warning "Can not find $Idenity"
        }
        else {
            $Name
        }
    }
    else {
        if ($null -eq $Name) {
            Write-Verbose "Testing Name"
            try {
                $Name = (Get-ADUser -Filter "name -like '*$Idenity*'" -Properties Samaccountname ).samaccountname | Sort-Object
            }
            catch {
                $Name = $null
            }
            if ($null -eq $Name) { Write-Verbose "Failed Name" }
        }
        if ($null -eq $Name) {
            Write-Verbose "Testing GivenName"
            try {
                $Name = (Get-ADUser -Filter "GivenName -like '$Idenity'" -Properties Samaccountname ).samaccountname | Sort-Object
            }
            catch {
                $Name = $null
            }
            if ($null -eq $Name) { Write-Verbose "Failed GivenName" }
        }
        if ($null -eq $Name) {
            Write-Verbose "Testing Surname"
            try {
                $Name = (Get-ADUser -Filter "Surname -like '$Idenity'" -Properties Samaccountname ).samaccountname | Sort-Object
            }
            catch {
                $Name = $null
            }
            if ($null -eq $Name) { Write-Verbose "Failed Surname" }
        }
        if ($null -eq $Name) {
            Write-Verbose "Testing SID"
            try {
                $Name = (Get-ADUser -Filter "SID -like '$Idenity'" -Properties Samaccountname ).samaccountname | Sort-Object
            }
            catch {
                $Name = $null
            }
            if ($null -eq $Name) { Write-Verbose "Failed SID" }
        }
        if ($null -eq $Name) {
            Write-Verbose "Testing DistinguishedName"
            try {
                $Name = (Get-ADUser -Filter "DistinguishedName -like '*$Idenity*'" -Properties Samaccountname ).samaccountname | Sort-Object
            }
            catch {
                $Name = $null
            }
            if ($null -eq $Name) { Write-Verbose "Failed Distinguishedname" }
        }
        if ($null -eq $Name) {
            Write-Verbose "Testing Samaccountname"
            try {
                $Name = (Get-ADUser -Filter "SamAccountName -like '*$Idenity*'" -Properties Samaccountname ).samaccountname | Sort-Object
            }
            catch {
                $Name = $null
            }
            if ($null -eq $Name) { Write-Verbose "Failed Samaccountname" }
        }
        if ($null -eq $Name) {
            Write-Verbose "Testing ObjectGUID"
            try {
                $Name = (Get-ADUser -Filter "ObjectGUID -like '*$Idenity*'" -Properties Samaccountname ).samaccountname | Sort-Object

            }
            catch {

                $Name = $null
            }
            if ($null -eq $Name) { Write-Verbose "Failed ObjectGUID" }
        }
        $AllUsers = Get-ADUser -Filter * -Properties Samaccountname, EmployeeID, EmployeeNumber, Office, Mail, Department, City
        if ($null -eq $Name) {
            Write-Verbose "Testing EmployeeID"
            try {
                $Name = ($AllUsers | Where-Object { $_.EmployeeID -like "*$Idenity*" }).samaccountname | Sort-Object
            }
            catch {
                $Name = $null
            }
            if ($null -eq $Name) { Write-Verbose "Failed EmployeeID" }
        }
        if ($null -eq $Name) {
            Write-Verbose "Testing EmployeeNumber"
            try {
                $Name = ($AllUsers | Where-Object { $_.EmployeeNumber -like "*$Idenity*" }).samaccountname | Sort-Object
            }
            catch {
                $Name = $null
            }
            if ($null -eq $Name) { Write-Verbose "Failed EmployeeNumber" }
        }
        if ($null -eq $Name) {
            Write-Verbose "Testing Office"
            try {
                $Name = ($AllUsers | Where-Object { $_.Office -like "*$Idenity*" }).samaccountname | Sort-Object
            }
            catch {
                $Name = $null
            }
            if ($null -eq $Name) { Write-Verbose "Failed Office" }
        }
        if ($null -eq $Name) {
            Write-Verbose "Testing Email Address"
            try {
                $Name = ($AllUsers | Where-Object { $_.EmailAddress -like "*$Idenity*" }).samaccountname | Sort-Object

            }
            catch {
                $Name = $null
            }
            if ($null -eq $Name) { Write-Verbose "Failed EmailAddress" }
        }
        if ($null -eq $Name) {
            Write-Verbose "Testing Department"
            try {
                $Name = ($AllUsers | Where-Object { $_.Department -like "*$Idenity*" }).samaccountname | Sort-Object
            }
            catch {
                $Name = $null
            }
            if ($null -eq $Name) { Write-Verbose "Failed Department" }
        }
        if ($null -eq $Name) {
            Write-Verbose "Testing City"
            try {
                $Name = ($AllUsers | Where-Object { $_.City -like "*$Idenity*" }).samaccountname | Sort-Object
            }
            catch {

                $Name = $null
            }
            if ($null -eq $Name) { Write-Verbose "You failed this city" }
        }
        if ($null -eq $Name) {
            write-warning "Can not find $Idenity"
        }
        else {
            $Name
        }
    }
} #Review - Testing, Documentation