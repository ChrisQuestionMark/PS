#CleanTemp
function Clean-Temp ([string[]]$Computers = $(Read-Host "Remote Computer Name").toUpper(),[int]$maxConcurrentJobs = 20){
	#Region Init
		[Double]$totalSpaceSaved = 0
		[int]$intCompCounter = 1
		[int]$intComputers = $colComputers.length
		$results = @()
		$colComputers = $Computers
		
	#EndRegion
	
	
	
	$ScriptCleanTemp = {	
		param(
			[String]$strComputer,
			[switch]$progress
		)
		$additionalFolders = @(
			'C:\ProgramData\Microsoft Visual Studio\10.0\TraceDebugging',
			'C:\Documents and Settings\All Users\Application Data\Microsoft Visual Studio\10.0\TraceDebugging'
		)
		#Additional Functions
		function Get-RemotePath ([String]$strLocal) { "\\" + $strComputer + "\" + $strLocal.Replace(":","$") }
		function Get-LocalPath ([String]$strRemote){ 
			$i = $strRemote.IndexOf("`$")
			$d = $strRemote.Chars($i-1)
			$newPath = $d + ":" + $strRemote.Substring($i+1)
			$newPath
		}
		Function Start-PSExec ([String]$Computer,[String]$psCommand){
			[int]$timeout = 20
			$psexecEXE = 'psexec.exe'
			$tempFile = [System.IO.Path]::GetTempFileName()
			$startParam = "\\$Computer -d $psCommand"
			
			#Define and start process
			$pinfo = New-Object System.Diagnostics.ProcessStartInfo
			$pinfo.FileName = $psexecEXE
			$pinfo.Arguments = $startParam
			$pinfo.WindowStyle = 'Hidden'
			$pinfo.CreateNoWindow = $true
			$pinfo.RedirectStandardError = $true
			$pinfo.RedirectStandardOutput = $true
			$pinfo.UseShellExecute = $false
			$p = New-Object System.Diagnostics.Process
			$p.StartInfo = $pinfo
			$p.Start() | Out-Null
			
			#Wait for process to start
			$counter = 1
			while ($p.HasExited -eq $false -and $counter -le $timeout){
				Start-Sleep -Seconds 1	
				$counter++
			}
			
			#Return ProcID or error
			$output = $p.StandardError.ReadToEnd()
			$a = $output
			$b = $a.Split('.') | ?{ $_ -like '*process ID*' }
			if ($b){
				[int]$ID = $b.Split(' ') | Select -Last 1
				return $ID
			} Else {
				$o = $output.Split("`r") | %{ $_.Trim() } | ?{ $_ }
				if ($o -and $o.Length -ge 4){
					$o[3]
				}
			}
		}
		
		$objResult = "" | Select 'ComputerName','Letter','Volume','Size_GB','FreeSpace_GB','SpaceSaved_MB','Result'
		$objResult.ComputerName = $strComputer

		#Test Connectivity
		if ($progress){
			Write-Progress -Activity "Clean-Temp - $strComputer" -Status "Checking Connectivity"
		}
		if (!(Test-Connection $strComputer -Quiet))
		{
			$objResult.Result = 'Host Unreachable'
			$results += $objResult
			$objResult
			Continue
			
		}

			#Remote Registry Enabled
			try{
				$RemoteRegistry = Get-WmiObject win32_service -computername $strComputer -errorvariable wmiError -ErrorAction SilentlyContinue | Where-Object { $_.Name -EQ "RemoteRegistry"} 
			}Catch{
				$objResult.Result = 'Host Unreachable'
				$objResult
				Continue
			}
			
			if ($RemoteRegistry -and $RemoteRegistry.State -NE "Running"){
				#Write-Host -ForegroundColor Yellow "Enabling Remote Registry Service"
				$RemoteRegistry.StartService() | Out-Null
				$RemoteRegistry.ChangeStartMode("Automatic") | Out-Null
			}
			
			try {
				$regLM = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $strComputer)
				$regUsers = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('Users', $strComputer)
			} Catch { 
				$objResult.Result = 'Failed to read registry'
				$objResult
				Continue
			}
			$colCleanFolders = @() #Create empty array to hold all of the locations to delete files
			$colDelFolders = @() #Create empty array to hold folders to be deleted
			
			#Get Starting freespace on each drive
			try {
				$wmiDisksBefore = Get-WmiObject win32_logicaldisk -ComputerName $strComputer | Where-Object{ $_.DriveType -eq 3} | Select-Object DeviceID,VolumeName,Size,FreeSpace
			} Catch {
				$objResult.Result = "Failed: $_"
				Continue
			}
			$diskArrayBefore = @()
			$diskArrayBefore += $wmiDisksBefore
			
			#Use WMI to get local drive letters and look for specific folders on the root of each drive
			$driveLetters = @()
			gwmi win32_logicaldisk -ComputerName $strComputer | Where-Object {$_.DriveType -EQ 3 } | ForEach-Object { $driveLetters += $_.DeviceID.Substring(0,1) }
			foreach ($L in $driveLetters){
				$strRootTemp = "\\$strComputer\$L`$\Temp"
				$strRecycler = "\\$strComputer\$L`$\Recycler"
				if ($strRootTemp -and (Test-Path $strRootTemp)){ $colCleanFolders += Get-LocalPath $strRootTemp }
				if ($strRecycler -and (Test-Path $strRecycler)){ $colCleanFolders += Get-LocalPath $strRecycler }
			}
			
			#Altiris Software Cache
			try { $regAltiris = $regLM.OpenSubKey('SOFTWARE\\Altiris\\Altiris Agent') } Catch {}
			if ($regAltiris){
				$altirisDir = $regAltiris.GetValue('InstallDir')
				$altirisDir = $altirisDir + '\Agents\SoftwareManagement\Software Delivery'
				$colDelFolders += $altirisDir
			}
			
			#Additional Folders
			Foreach ($folder in $additionalFolders){
				$remFolder = Get-RemotePath $folder
				if ($remFOlder -and (Test-Path $remFolder)){
					$colCleanFolders += $folder
				}
			
			}
			
			#Windows\Temp folder
			if ($progress){
				Write-Progress -Activity "Clean-Temp - $strComputer" -Status "Getting Files/Folders to Delete"
			}
			$regWinNT = $regLM.OpenSubKey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion")
			$str = $regWinNT.GetValue("SystemRoot")
			$str = $str + "\" + "Temp"
			$strWinTemp = Get-RemotePath $str
			if ( $strWinTemp -and (Test-Path $strWinTemp)){ $colCleanFolders += Get-LocalPath $strWinTemp }
			
			#Search through each user profile    
			#Write-Host -ForegroundColor Yellow "Getting list of target folders..."
			$regShellFolders = $regLM.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders")
			$strCommonDesktop = $regShellFolders.getValue('Common Desktop')
			if ($strCommonDesktop.Contains('\')){
				$strProfiles = $strCommonDesktop.substring(0,$strCommonDesktop.IndexOfAny('\',3))
			}
			$strProfiles = Get-RemotePath $strProfiles
			
			Get-ChildItem $strProfiles  | ForEach-Object {
				$strTemp = $strProfiles + '\' + $_.name + '\Local Settings\Temp'
				$strAppDataTemp = $strProfiles + '\' + $_.name + '\AppData\Local\Temp'
				$strTempInternet = $strProfiles + '\' + $_.name + '\Local Settings\Temporary Internet Files'
				$strTemp = $strProfiles + '\' + $_.name + '\Local Settings\Temp'
				if ($strTemp -and (Test-Path $strTemp)){ $colCleanFolders += Get-LocalPath $strTemp }
				if ($strAppDataTemp -and (Test-Path $strAppDataTemp)){ $colCleanFolders += Get-LocalPath $strAppDataTemp }
				if ($strTempInternet -and (Test-Path $strTempInternet)){ $colCleanFolders += Get-LocalPath $strTempInternet }
			} 
		
		#Delete hidden folders under Windows folder
		#Add check for folders over 60days
		$winDir = Get-RemotePath $regWinNT.GetValue("SystemRoot")
		Get-ChildItem -Path $winDir -Force `$Nt* | Where-Object {$_.CreationTime -LT (Get-Date).AddDays(-60)} | ForEach-Object {
				$colDelFolders += Get-LocalPath $_.FullName
		}
		
		#System Recovery Folders
		if (Test-Path $(Get-RemotePath 'C:\System Volume Information') -ErrorAction SilentlyContinue){
			Get-ChildItem -force "$(Get-RemotePath 'C:\System Volume Information')\*\RP*" | %{
				$colDelFolders += Get-LocalPath $_.FullName
			}
		}
		
		if (Test-Path $(Get-RemotePath 'D:\System Volume Information')){
			Get-ChildItem -force "$(Get-RemotePath 'D:\System Volume Information')\*\RP*" | %{
				$colDelFolders += Get-LocalPath $_.FullName
			}
		}
		
		#List folders for cleaning and deletion. Create batch file on remote system.
		#Write-Host -ForegroundColor Red "Preparing to CLEAN the following folders: "    
		if ($progress){
			Write-Progress -Activity "Clean-Temp - $strComputer" -Status "Building remote script"
		}
		#$cmd = "$winDir\System32\cmd.exe /c $winDir\CleanTemp.cmd"
		$remBatch = "$winDir\CleanTemp.cmd"
		if ($remBatch -and (Test-Path $remBatch)){ Remove-Item $remBatch }
		foreach ($s in $colCleanFolders){
				#Write-Output "del /q /f /s `"$s`" `>`> C:\Windows\CleanTemp.txt" | Out-File -Encoding "Default" -Append -NoClobber -FilePath $cmd
				try {
					Write-Output "echo Clean Folder - `"$s`" `>`> C:\Windows\CleanTemp.txt" | Out-File -Encoding "Default" -Append -NoClobber -FilePath $remBatch
					Write-Output "rmdir /s /q `"$s`" `>`> C:\Windows\CleanTemp.txt" | Out-File -Encoding "Default" -Append -NoClobber -FilePath $remBatch
					Write-Output "mkdir `"$s`" `>`> C:\Windows\CleanTemp.txt" | Out-File -Encoding "Default" -Append -NoClobber -FilePath $remBatch
				} Catch [System.IO.IOException]{
					Write-Host -ForegroundColor Red "$_"
					$remPath = Get-RemotePath $s
					if ($remPath -and (Test-Path $remPath)){
						Get-ChildItem $remPath -Force -ErrorAction SilentlyContinue | %{
							if($progress){
								Write-Progress -Activity "Clean-Temp - $strComputer" -Status "Building remote script" -CurrentOperation "Deleting $_"
							}
							try{
								Remove-Item -Force -ErrorAction SilentlyContinue -Recurse -Path $($_.FullName)
							} Catch {}
						}
					}
				}
			}
		#Write-Host -ForegroundColor Red "Preparing to DELETE the following folders: "    
		foreach ($d in $colDelFolders){
			try {
				Write-Output "echo Delete Folder - `"$d`" `>`> C:\Windows\CleanTemp.txt" | Out-File -Encoding "Default" -Append -NoClobber -FilePath $remBatch
				Write-Output "rmdir /s /q `"$d`" `>`> C:\Windows\CleanTemp.txt" | Out-File -Encoding "Default" -Append -NoClobber -FilePath $remBatch
			} Catch [System.IO.IOException]{
				Write-Host -ForegroundColor Red "$_"
				$remPath = Get-RemotePath $s
				if ($remPath){
					Get-ChildItem $remPath -Force -ErrorAction SilentlyContinue | %{
					if($progress){
						Write-Progress -Activity "Clean-Temp - $strComputer" -Status "Building remote script" -CurrentOperation "Deleting $_"
					}
						try {
							Remove-Item -Force -ErrorAction SilentlyContinue -Recurse -Path $($_.FullName)
						} Catch {}
					}
				}
			}
		}
			#Start remote process
		if ($progress){
			Write-Progress -Activity "Clean-Temp - $strComputer" -Status "Starting Remote Process"
		}
			$mc = new-object System.Management.ManagementClass "\\$strComputer\root\cimv2:Win32_Process"
			$locCMD = Get-LocalPath $remBatch
			try {
				$result = $mc.create($locCMD)
				$return = $result.ReturnValue
				$procID = $result.ProcessId
			} Catch {
				$objResult.Result = "Failed to start WMI Process: $_"
			}
			if($return -ne 0) {
				$psResult = Start-PSExec -Computer $strComputer -psCommand $locCMD
				if ($psResult.GetType().Name -eq 'Int32'){
					$procID = $psResult
				} Else {
					$objResult.Result = "Failed to start PSEXEC process: $psResult"
					$d = $diskArrayBefore | Select -First 1
					$driveSize = [Math]::Round($d.Size / 1gb,2)
					$driveFreeSpace = [Math]::Round($d.FreeSpace / 1gb,2)
					$objResult.Letter = $d.DeviceID
					$objResult.Volume = $d.Caption
					$objResult.Size_GB = $driveSize
					$objResult.FreeSpace_GB = $driveFreeSpace
					$objResult
					if ($progress){
						Write-Progress -Activity "Clean-Temp - $strComputer" -Status "Remotely Deleting Files"
					}
					$colCleanFolders | %{ 
						$rPath = Get-RemotePath $_
						if ($progress){ Write-Progress -Activity "Clean-Temp - $strComputer" -Status "Remotely Deleting Files" -CurrentOperation $rPath }
						Get-ChildItem $rPath -Force | Remove-Item -Force -Recurse 
					}
					$colDelFolders | %{
						$rPath = Get-RemotePath $_
						if ($progress){ Write-Progress -Activity "Clean-Temp - $strComputer" -Status "Remotely Deleting Files" -CurrentOperation $rPath }
						Get-ChildItem $rPath -Force | Remove-Item -Force -Recurse 
					}
					#Continue
				}
				#$objResult.Result = 'Failed to start remote process'
			} 
			
			#Write-Host -ForegroundColor Yellow "Waiting for the remote process to complete. This could take several minutes."
			While (Get-Process -ComputerName $strComputer -Id $procID -ErrorAction SilentlyContinue){
				if ($progress){
					$file = Get-Content "$winDir\CleanTemp.txt" -ErrorAction SilentlyContinue | Select-Object -Last 1
					if ($file){Write-Progress -Activity "Cleaning [$intCompCounter/$intComputers] $strComputer" -CurrentOperation $file.SubString($file.LastIndexOf("\")+1) -Status $file}
				}
			}
			
			#Remove batch file and log
			if ($remBatch -and (Test-Path "$remBatch")){ 
				Remove-Item -Force $remBatch 
				$cmdLog = $remBatch.Replace('.cmd','.txt')
				if ($cmdLog -and (Test-Path $cmdLog)){ Remove-Item -Force $cmdLog }
			}
			
			#Find difference and total space saved
			$wmiDisksAfter = Get-WmiObject win32_logicaldisk -ComputerName $strComputer | Where-Object{ $_.DriveType -eq 3} | Select-Object DeviceID,VolumeName,Size,FreeSpace
			#Write-Host -ForegroundColor Green "Results"
			$diskArrayAfter = @()
			$diskArrayAfter += $wmiDisksAfter
			for ($i=0;$i -lt $diskArrayAfter.Length;$i++){
				if ($objResult.letter){
					$objResult = "" | Select 'ComputerName','Letter','Volume','Size_GB','FreeSpace_GB','SpaceSaved_MB','Result'
					$objResult.ComputerName = $strComputer
					#$objResult = New-Object System.Object
					#$objResult | Add-Member NoteProperty "ComputerName" $strComputer
				}
				
				$driveSize = [Math]::Round($diskArrayAfter[$i].Size / 1gb,2)
				$driveFreeSpace = [Math]::Round($diskArrayAfter[$i].FreeSpace / 1gb,2)
				$driveSpaceSaved = [Math]::Round(($diskArrayAfter[$i].FreeSpace - $diskArrayBefore[$i].FreeSpace) / 1mb,2)
				
				$objResult.Letter = $diskArrayAfter[$i].DeviceID
				$objResult.Volume = $diskArrayAfter[$i].VolumeName
				$objResult.Size_GB = $driveSize
				$objResult.FreeSpace_GB = $driveFreeSpace
				$objResult.SpaceSaved_MB = $driveSpaceSaved
				if ($driveSpaceSaved -gt 0){
					$objResult.Result = 'Success'
				} Else { $objResult.Result = "No space saved" }
				
				#Return
				$objResult
				#$objResult | Format-List * | Write-Output
				

	#			if ($i -ne ($diskArrayAfter.Length)){
	#				Write-Host -ForegroundColor Green 'Writing results'
	#				
	#			}
				#$results += $objResult 
				#$totalSpaceSaved += ($diskArrayAfter[$i].FreeSpace - $diskArrayBefore[$i].FreeSpace)
			}
			
		}
	
		
		
			#Region ExecuteScript
			if ($colComputers.length -eq 1)
			{
				$results = $ScriptCleanTemp.Invoke($colComputers[0],$true)
			} Else {
			
			#Build Queue
			$queue = [System.Collections.Queue]::Synchronized( (New-Object System.Collections.Queue) )
			$colComputers | %{ $queue.Enqueue($_) }
			$colJobs = @()
			$intJobCounter = 1
			
			While ($queue.Count -gt 0){
				if (($colJobs | ?{ $_.State -eq 'Running' }).length -le $maxConcurrentJobs ){
					$strComputer = $queue.Dequeue()
					Write-Progress -Activity "Creating Background Jobs" -Status "$strComputer [$(($colComputers.length) - $($queue.count))/$($colComputers.length)]" -PercentComplete ((($($colComputers.length) - $($queue.count)) / ($($colComputers.length))) * 100 ) -CurrentOperation "$(($colJobs | ?{ $_.State -eq 'Running' }).length) jobs currently running"
					$colJobs += Start-Job -name $strComputer -ScriptBlock $ScriptCleanTemp -ArgumentList @($strComputer)
				}	
			}
			
			#Wait for jobs to finish
			$jobsPending = $colJobs | Get-Job | ?{ $_.State -eq 'Running' }
			While ($jobsPending){
				if ($jobsPending.length -gt 1){ 
					[int]$intPending = $jobsPending.Length
				} Else { [int]$intPending = 1 }
				Write-Progress -Activity "All Jobs created" -Status "Waiting for $intPending background jobs to complete" -CurrentOperation $(($jobsPending | Select -first 1).Name)
				$jobsPending = $colJobs | Get-Job | ?{ $_.State -eq 'Running' }
			}
			
			#Recieve results
			$colJobs | Receive-Job | Select -Property * -ExcludeProperty RunspaceId,PSComputerName | %{ $results += $_ }
			
			
		}
		
		#EndRegion
		#Region Completed
		$colJobs.length
		$results
		[int]$totalSpaceSaved_MB = ($results | ?{ $_.SpaceSaved_MB -gt 0 } | Measure-Object -Property SpaceSaved_MB -Sum).Sum
		$totalSpaceSaved = [Math]::Round($totalSpaceSaved_MB / 1kb,2)
		$totalComputers = ($results | ?{ $_.Result -eq 'Success' } | Select-Object -Unique ComputerName).Length
		if ($totalComputers -eq $null){ $totalComputers = 1 }
		Write-Host -ForegroundColor Green "$totalSpaceSaved GBs saved over $totalComputers computers"
		
		if ($colComputers.length -gt 1 -and $results.length -gt 1){
			$strDate = Get-Date -Format "yy-MM-dd.HH.mm.ss"
			$strPath = "$env:temp\CleanTemp.$strDate.csv"
			$results | Export-Csv -NoTypeInformation -Path $strPath
			. $strPath
		} else { $results }
		#Endregion	
	}