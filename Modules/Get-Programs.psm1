Function Get-Programs ([String]$Computer){
	Write-Progress -Activity "Getting Installed Programs" -Status "Checking connectivity of $Computer"
	if (!(Test-Connection $Computer -Quiet -Count 2)){
		"Host Unreachable"
	} Else {
		 #Remote Registry Enabled
	    try {
			$RemoteRegistry = Get-WmiObject win32_service -computername $Computer -errorvariable wmiError -ErrorAction SilentlyContinue | Where-Object { $_.Name -EQ "RemoteRegistry"} 
		} Catch {
			"Unable to connect to $Computer - $_"
	        continue
		}
	    if ($RemoteRegistry -and $RemoteRegistry.State -NE "Running"){
			Write-Progress -Activity "Establishing Connection"  -Status "Enabling Remote Registry" -CurrentOperation "Please Wait"
	        $RemoteRegistry.StartService() | Out-Null
	        $RemoteRegistry.ChangeStartMode("Automatic") | Out-Null
	    }
		
		$regLM = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $Computer)
		$objPrograms = @()
		$arch = $regLM.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment").GetValue("PROCESSOR_ARCHITECTURE")
		if ($arch -eq 'x86'){
			$colUninstall = @("Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall")
			$strOffice = 'SOFTWARE\\Microsoft\\Office'
		} Else {
			$colUninstall = @("Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall","SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall")
			$strOffice = 'SOFTWARE\\Wow6432Node\\Microsoft\\Office'
		}
		
		#Check Office Apps 
		$regOffice = $regLM.OpenSubKey($strOffice)
		foreach ($ver in $regOffice.GetSubKeyNames() | ?{ $_.Contains('.') }){
			$regOfficeVer = $regOffice.OpenSubKey($ver)
			foreach ($prod in $regOfficeVer.GetSubkeyNames()){
				$regProd = $regOfficeVer.OpenSubKey($prod)
				if ($regProd.GetSubkeyNames() | ?{ $_ -eq 'InstallRoot' }){
					$objProgram = '' | Select Program,Version
					$objProgram.Program = "Microsoft Office $prod"
					$objProgram.Version = $ver
					$objPrograms += $objProgram
				}
			}
		}
		
		#Check Uninstall Registry Keys
		 $colUninstall | %{
			$regLMKey = $regLM.OpenSubKey($_)
			foreach($sub in $regLMKey.GetSubKeyNames()){
				if($sub -NOTLIKE "KB*" -and $sub -notlike "*}.KB*" -and $sub -notlike "*0FF1CE}*" -AND $regLMKey.OpenSubKey($sub).GetValue("DisplayName") ){
					[String]$strProg = $regLMKey.OpenSubKey($sub).GetValue("DisplayName")
					Write-Progress -Activity "Getting Installed Programs" -Status "Collecting Installed Software" -CurrentOperation $strProg
					$objProgram = '' | Select Program,Company,Version
					$objProgram.Program = $strProg
					$objProgram.Version = $regLMKey.OpenSubKey($sub).GetValue("DisplayVersion")
					$objProgram.Company = $regLMKey.OpenSubKey($sub).GetValue("Publisher")
					if (!($objPrograms | ?{ $_.Program -eq $objProgram.Program -and $_.Version -eq $objProgram.Version })){
						#If its not already in the results, add it.
						$objPrograms += $objProgram
					}
				}
			}
		}
		$objPrograms = $objPrograms | Sort-Object -Property "Program"
		$objPrograms
	}
}


