function Get-Joke {
    <#
    .SYNOPSIS
        Grabs a joke from Reddit.
    .DESCRIPTION
        Grabs a joke from reddit.
    .PARAMETER Type
        Validated Set of "Clean","Dad","Joke"
    .EXAMPLE
        PS> Get-joke -Type clean

        I used to a trusted member of a totally secret cooking society. But they kicked me out ..
        .. for spilling the beans.
    .INPUTS
    .OUTPUTS
        A Joke
    .NOTES
        Author: David Bolding
        Date: 10/15/2020
    .LINK
        https://github.com/rndadhdman/PS_Super_Helpdesk
    #>
[CmdletBinding()]
param (
    [Parameter(HelpMessage = "Type of Joke, Dad or Clean", Mandatory = $True)][validateset("Dad", "Clean", "Joke")]$Type = "Clean"
)
if ($Type -like "Dad") {
    $Test = Invoke-RestMethod -Uri "https://www.reddit.com/r/dadjokes/top.json" -UseBasicParsing
    $URL = "https://www.reddit.com/r/dadjokes/top"
}
elseif ($Type -like "Joke") {
    $Test = Invoke-RestMethod -Uri "https://www.reddit.com/r/Jokes/top.json" -UseBasicParsing
    $URL = "https://www.reddit.com/r/Jokes/top"
}
elseif ($Type -like "Clean") {
    $Test = Invoke-RestMethod -Uri "https://www.reddit.com/r/cleanjokes/top.json" -UseBasicParsing
    $URL = "https://www.reddit.com/r/cleanjokes/top"
}
else {
    $Test = Invoke-RestMethod -Uri "https://www.reddit.com/r/dadjokes/top.json" -UseBasicParsing
    $URL = "https://www.reddit.com/r/dadjokes/top"
}

$Joke = $Test.data.children[0]
write-host "$($Joke.data.title)"
write-host "$($Joke.data.selftext)"
}
