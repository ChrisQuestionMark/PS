Write-Host -foreground Green "Installing Chris' Scripts..."
$myURL = 'http://github.com/ChrisQuestionMark/PS/tree/master/Modules'
[regex]$regModules = 'href=\".*\/\S*\.psm1\"'
$wc = New-Object System.Net.WebClient
$myPage = $wc.DownloadString($myURL)
$matches = $regModules.Matches($myPage).Value
$matches
if ($matches -and $matches -like '*"*"*' )
{
    $matches | %{ 
        $module = $_.Split('"')[1].replace('blob/','')
        $moduleURL = 'http://raw.github.com' + $module
        Write-Host "`t Getting $moduleURL"
        $wc.DownloadString($moduleURL) | Invoke-Expression
    }
}




