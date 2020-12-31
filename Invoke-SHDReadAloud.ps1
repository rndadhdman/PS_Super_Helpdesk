function Invoke-SHDReadAloud {
    <#
    .SYNOPSIS
        Reads a list of strings out loud.
    .DESCRIPTION
        Reads a list of strings out loud.
    .PARAMETER Message
        The list of strings you wish to be read outloud with the standard voice. 
    .EXAMPLE
        PS> Get-SHDReadALoud -Message "We're No strangers to love","You know the rules and so do I","A full commitment's what I'm thinking of","You wodln't get this from any other guy"
    .INPUTS
        List of strings
    .OUTPUTS
        Sound
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
            HelpMessage = "Read This Message",
            Mandatory = $true)][Alias('Words', 'Speech')][String[]]$Message
    )
    add-type -assemblyname system.speech
    $talk = new-object System.Speech.Synthesis.SpeechSynthesizer
    foreach ($Item in $Message) {
        $talk.Speak($Item)
        start-sleep -Seconds 2
    }
}

