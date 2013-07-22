Function Stop-ScreenSaver 
{
	<#		.SYNOPSIS
			Simulates key input to prevent screensaver.
			
			.PARAMETER Minutes
			How long you want the script to run.
			
			.PARAMETER Key
			The key that it will press. 
			http://technet.microsoft.com/en-us/library/ee156592.aspx
	
	#>
	param
	(
		$minutes = 60,
		$key = '{F15}'
	)
	$myshell = New-Object -com "Wscript.Shell"
	$startTime = Get-Date
	$endTime = $startTime.AddMinutes($minutes)
	
	While ((Get-Date) -lt $endTime)
	{
	  	Write-Progress -Activity "Pressing button" -Status "Last run on $lastRun" -SecondsRemaining $(New-TimeSpan -Start (Get-Date) -End $endTime).TotalSeconds
	  	if (!$lastRun -or $(Get-Date).Second -eq '00')
		{
			$lastRun = Get-Date
			$myshell.sendkeys($key)
		}
	}
}
