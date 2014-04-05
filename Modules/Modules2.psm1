	Function Get-ProcessTree ([String]$ComputerName = '.'){
		[String]$strComputer = $computerName
		if ($passthru)
		{
			$token = '	'
		}
		else
		{
			$token = '%S%'
		}
		Write-Progress -Activity "Creating Report" -Status "Collecting Processes" -CurrentOperation "Please Wait"
		$wmiProcess = get-wmiobject win32_process -computer $strComputer | ?{ $_.Path } | Sort ProcessID
		Function Get-ChildProcess ([System.Management.ManagementObject]$process,[int]$indent){
			Write-Progress -Activity "Creating Report" -Status "Collecting Processes" -CurrentOperation "$($process.name)"
			$process | Select @{Name='Path';Expression={"$token" * $indent + $_.path}},
				@{Name='User';Expression={"$token" * $indent + $($_.getOwner().User)}},
				@{Name="creationDate"; Expression={"$token" * $indent + ([System.Management.ManagementDateTimeconverter]::ToDateTime($_.CreationDate)).GetDateTimeFormats()[46]}}
			$indent++
			$wmiProcess | ?{ $_.ParentProcessID -eq $process.ProcessID } | %{
				Get-ChildProcess $_ $indent
			}
		}
		
		foreach ($p in $wmiProcess){
			if (! ($wmiProcess | ?{ $_.ProcessID -eq $p.ParentProcessId } ) ){
				Get-ChildProcess $p 0
			}
		}
	}