Function Get-Info {
<#		.SYNOPSIS
			Gathers information from a remote Windows machine that is useful to support personnel.

		.PARAMETER Computer
	    	Required. The name of the remote computer. If you do not specify one, you will be prompted.
			
		.PARAMETER Services 	
			Includes Non-Microsoft services from the remote machine. This can take some time over a slow connection.
		
		.PARAMETER EventLog
			Queries the System and Application eventlogs for Warning or Error messages from the past 7 days. This takes a very long time to complete.
		
		.PARAMETER Programs
			Lists all installed software excluding hotfixes.
			
		.PARAMETER PassThru
			Returns an object with all of the properties collected

		.EXAMPLE
			PS C:\> Get-Info -passthru Chris-Computer
				Displays basic information about computer RETDAYV-9600006 to the console.
		.EXAMPLE
			PS C:\> Get-Info -services -programs -eventlog Chris-Computer
				Creates and opens an HTML file that contains all possible information about the computer RETDAYV-9600006.
		
		.NOTES
			Created by Chris Pawel (Chris.Pawel@ReedElsevier.com)
#>
	[CmdletBinding()]
	Param(
	[Parameter(ValueFromPipeline=$true,Mandatory=$true)] [ValidateNotNullOrEmpty()]
		[string] $Computer,
	[Parameter()]
		[switch] $Services,
	[Parameter()]
		[switch] $Programs,
	[Parameter()]
		[switch] $EventLog,
	[Parameter()]
		[switch] $HotFixes,
	[Parameter()]
		[switch] $PassThru
	)
	
	#Region Helpers
	#Create a function to write output either to the console or an HTML file
	Function Write-Object ([String]$strTitle,$objResult,[String]$type){
		If ($PassThru){
			if ($objResult -like '*%S%*'){
				$repObj = $objResult -replace '%S%','    '
				$objResult = foreach ($s in $repObj){
					New-Object -TypeName PSObject -Property $(Invoke-Expression $s.Replace('=','="').Replace(';','";').Replace('}','"}'))
				}
			}
			$objResults | Add-Member -MemberType NoteProperty -Name $strTitle -Value $objResult
		}
		else
		{
			#Write-HTML
			$i = 1
			Write-Output $objResult | ConvertTo-Html -As $type -Body "<H2> $strTitle </H2>" | %{ 
				if ($i % 2 -eq 1){
					$s = $_.Replace('<td>','<td class="datacellone">')
				} Elseif ($i % 2 -eq 0) {
					$s = $_.Replace('<td>','<td class="datacelltwo">')
				}
				$s = $s.Replace('&amp;','&')
				$s.Replace('%S%','&nbsp;&nbsp;&nbsp;&nbsp;')
				$i++
			} | Out-File -Append $htmlFileName
		}
	}
	
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
	
	#Function to get Events on Win7
	Function Get-WinEventCustom {
			param (
				[Parameter(ValueFromPipeline=$true,Mandatory=$true)] [ValidateNotNullOrEmpty()]
				$Computer,
				$intDays = 30,
				$logName = 'System',
				$level = 2
			)
			$filterHash = @{
				LogName=$logName
				Level=$level;
				StartTime=$((Get-Date).AddDays(-$intDays));
			}
			try {
				Write-Progress -Activity "Creating Report"  -Status "Getting Events" -CurrentOperation "$logName"
				$colEvents = Get-WinEvent -ComputerName $Computer -ErrorAction Stop -MaxEvents 1000 -FilterHashtable $filterHash
			}Catch{}
			if ($colEvents){
				$colEvents | Select TimeCreated,ProviderName,ID,Message | Group-Object Providername,ID | Select Count,Name,@{n='Latest';e={($_.Group | Select -First 1).TimeCreated}},@{n='Message';e={($_.Group | Select -First 1).Message}} | Sort Count -Descending
			}
		}
		
	#Function to get events on XP
	Function Get-EventLogCustom {
			param (
				[Parameter(ValueFromPipeline=$true,Mandatory=$true)] [ValidateNotNullOrEmpty()]
				$Computer,
				$intDays = 30,
				$logName = 'System',
				$entryType = @("error","warning"),
				$max = 1000
			)
			try {
				Write-Progress -Activity "Creating Report"  -Status "Getting $logName Events" -CurrentOperation "This will take several minutes"
				$colEvents = Get-EventLog -ComputerName $Computer -LogName $logName -EntryType $entryType -After $((Get-Date).AddDays(-$intDays)) -Newest $max
			} Catch {}
			if ($colEvents){
				$colEvents | Select TimeGenerated,Source,EventID,Message | Group-Object Source,EventID | Select Count,Name,@{n='Latest';e={($_.Group | Select -First 1).TimeGenerated}},@{n='Message';e={($_.Group | Select -First 1).Message}} | Sort Count -Descending
			}
		
		}
		
	Function Get-UserProfiles ([String]$ComputerName = '.')
	{
		#if	($ComputerName -ne '.' -and !(Test-Connection -Quiet -Count 1 -ComputerName $ComputerName)){ return $null }
		if ((gwmi -ComputerName $ComputerName win32_Operatingsystem).Version -ge 6 ){
			#Vista added this WMI namespace to give us a user's last logonTime
			$colUsers = Get-WmiObject -ComputerName $ComputerName Win32_UserProfile | Select LocalPath,@{Name='LastUseTime';Expression={$_.ConvertToDateTime($_.LastUseTime) }}, SID
		} else {
			#Its more tricky in XP, doing some ludicrous calculation with values from the ProfileList will give similar results.
			$colUsers = @()
			$regLM = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName)
			$regProfileList = $regLM.OpenSubKey('SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList')
			foreach ($sid in $regProfileList.GetSubKeyNames())
			{
				$regProfile = $regProfileList.OpenSubKey($sid)
				$timeLow = $regProfile.GetValue('ProfileLoadTimeLow')
				$timeHigh = $regProfile.GetValue('ProfileLoadTimeHigh')
				$addDays = (($timeHigh * [Math]::Pow(2, 32) + $timeLow) / 600000000) / 1440
				$LastUseTime = (Get-Date "01/01/1601").AddDays($addDays)
				$userProfile = '' | Select LocalPath,LastUseTime,SID
				$userProfile.LocalPath = $regProfile.getValue('ProfileImagePath')
				$userProfile.SID = $sid
				$userProfile.LastUseTime = $LastUseTime
				$colUsers += $userProfile
			}
		}
		#Only list domain accounts
		$colUsers | ?{ $_.SID -like 'S-1-5-21-*' -and $_.SID -notlike 'S-1-5-21-*-500' -and $_.SID -notlike 'S-1-5-21-*-1???' } | Sort LastUseTime -Descending
		
	}
	
	Function Get-DellWarranty {
		Param([String]$ServiceTag);
		$result = @()
		if (!$ServiceTag){ return $result }
		Try{
			$AssetService = New-WebServiceProxy -Uri "http://xserv.dell.com/services/AssetService.asmx?WSDL";
			$ApplicationName = "AssetService";
			$Guid = [Guid]::NewGuid();
			$Asset = $AssetService.GetAssetInformation($Guid,$ApplicationName,$ServiceTag);	
			$item = $Asset | Select -ExpandProperty AssetHeaderData | Select *,StartDate,EndDate,DaysLeft,EntitlementType
			$war = $Asset | Select -ExpandProperty Entitlements | Sort EndDate | Select -Last 1
			$item.StartDate = $war.StartDate
			$item.EndDate = $war.EndDate
			$item.DaysLeft = $war.DaysLeft
			$item.EntitlementType = $war.EntitlementType
			$result += $item
		}
		Catch 
		{
			#Write-Host $($_.Exception.Message);	
		}
		return $result;
	}
	
	Function Get-HotFixDetails ([String]$Computer) {
		if ($Computer){
			$list = Get-HotFix -ComputerName $Computer |?{ $_.HotFixID -like "KB*" } |  Select HotFixID,InstalledOn
		} Else {
			$list = Get-HotFix |?{ $_.HotFixID -like "KB*" } | Select HotFixID,InstalledOn
			$Computer = $env:COMPUTERNAME
		}
		
		[String]$support = 'http://support.microsoft.com/kb/'
		[regex]$r = '<[^<]+?>(?<=^|>)[^><]+?(?=<|$)</title>'

		$result = @()
		$counter = 0
		foreach ($l in $list){
			$item = $l | Select HotFixID,InstalledOn,Bulletin,Description,ReleaseDate
			$counter++
			Write-Progress 'Getting Hotfix Information' -Status "[$counter/$($list.length)] $($l.HotFixID)"
			$kb = $l.HotFixID.Substring(2)
			$wc = New-Object System.Net.WebClient
			[String]$url = $support + $kb
			$content = $null
			try {
				$content = $wc.DownloadString($url)
			} Catch {}
			if ($content){
				$m = $r.Matches($content) | Select -First 1
				$desc = $null
				$desc = ($m.Value -replace "<.*?>").Trim()
				$colSplit = $desc.Split(':')
				if ($colSplit.Length -eq 1){
					$item.Description = $colSplit[0]
				} elseif ($colSplit.Length -eq 3){
					[String]$item.Bulletin = $colSplit[0]
					[String]$item.Description = $colSplit[1]
					$d = $null
					try {
						$d = [DateTime]($colSplit[2])
						$item.ReleaseDate = $d.ToShortDateString()
					} Catch {}
				}

			}
			$item
		}
	}	
	
	
	
	#EndRegion
	
	#Region Initialize
	Write-Progress -Activity "Establishing Connection"  -Status "Checking Connectivity" -CurrentOperation "Please Wait"
	if ($strComputer -and $strComputer -notlike '.' -and !(Test-Connection -Quiet $strComputer)){
	    Write-Host -BackgroundColor Black -ForegroundColor Red "$strComputer Unreachable"
       	continue
	}
	
	
	if (!(Get-Module | Where-Object {$_.Name -eq "PSTerminalServices"})){
		Try{Import-Module PSTerminalServices}
		Catch {}
	}
	$ErrorActionPreference = 'SilentlyContinue'
	$strComputer = $computer.toUpper()
	$objResults = New-Object PSObject
	#HTML Header
	if (!$passthru){
		if ($strComputer -ne '.'){
			$htmlFileName = "$env:TEMP\$strComputer.html"
			[String[]]$a = "<title>$strComputer : System Information</title>"
		} Else {
			$htmlFileName = "$env:TEMP\localMachine.html"
			[String[]]$a = "<title>System Information</title>"
		}
		$a += "<style>"
		$a += "BODY{background-color:white;}"
		$a += "TABLE{border-width: 1px;border-style: solid;border-color: black; font-size:20px; color:black; border-collapse: collapse;}"
		$a += "TH{border-width: 1px;padding: 0px;border-style: solid;border-color: black;background-color:darkorange}"
		$a += "td.datacellone { background-color: navajoWhite; color: black; }"
		$a += "td.datacelltwo { background-color: beige; color: black; }"
		$a += "</style>"
		[String]$strDate = Get-Date
		if ($strComputer -ne '.'){
			Convertto-Html -Head $a -Body "<H1>$strComputer - $strDate</H1>" | Out-File $htmlFileName
		} Else {
			Convertto-Html -Head $a -Body "<H1>$strDate</H1>" | Out-File $htmlFileName
		}
	}
	
	
    #Trap Exceptions
    Trap [System.UnauthorizedAccessException]{ 
        return Write-Host -BackgroundColor Black -ForegroundColor Red "Cannot connect to $strComputer - Access denied" 
    }   
    
    Trap [System.IO.IOException]{ 
        return Write-Host -BackgroundColor Black -ForegroundColor Red  "Cannot connect to registy on $strComputer - Network Path Not Found" 
    }   
    #Remote Registry Enabled
    $RemoteRegistry = Get-WmiObject win32_service -computername $strComputer -errorvariable wmiError -ErrorAction SilentlyContinue | Where-Object { $_.Name -EQ "RemoteRegistry"} 
    if ($wmiError) {
        Write-Host -BackgroundColor Black -ForegroundColor Red "RPC Server not available for: $strComputer"
        continue
    }
    if ($RemoteRegistry.State -NE "Running"){
		Write-Progress -Activity "Establishing Connection"  -Status "Enabling Remote Registry" -CurrentOperation "Please Wait"
        $RemoteRegistry.StartService() | Out-Null
        $RemoteRegistry.ChangeStartMode("Automatic") | Out-Null
    }
    
	#Create registry objects for later use 
    $regLM = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $strComputer)
    $regUsers = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('Users', $strComputer)
	
	#EndRegion
	
    #Region System Info
	Write-Progress -Activity "Creating Report"  -Status "Collecting System Information" -CurrentOperation "Please Wait"
	$objSystemInfo = New-Object PSCustomObject
    $wmiPerfOsSystem = Get-WmiObject -computer $strComputer -class Win32_PerfFormattedData_PerfOS_System -ErrorAction SilentlyContinue
    $wmiComputerSystem = Get-WmiObject -computer $strComputer -class Win32_ComputerSystem
    $wmiBios = Get-WmiObject -computer $strComputer -class Win32_Bios
    $wmiOS = Get-WmiObject -computer $strComputer -class Win32_OperatingSystem
    $wmiPerfOSMemory = Get-WmiObject -computer $strComputer -class Win32_PerfFormattedData_PerfOS_Memory -ErrorAction SilentlyContinue
    $wmiNet = Get-WmiObject -computer $strComputer -class Win32_NetworkAdapterConfiguration
	$wmiCPU = Get-WmiObject Win32_Processor -ComputerName $strComputer | Select-Object -First 1
    
    #Office Version
    if ($regLM.OpenSubKey("SOFTWARE\\Classes\\Word.Application\\CurVer")){
		Write-Progress -Activity "Creating Report"  -Status "Collecting System Information" -CurrentOperation "Getting Office Version"
        $regOffice = $regLM.OpenSubKey("SOFTWARE\\Classes\\Word.Application\\CurVer")
        $officeVerNum = $regOffice.GetValue("")
        $rx = [regex]'[\d]'
        $intOffice = $officeVerNum.Substring($rx.Match($officeVerNum).Index)
                       
		if ($regLM.OpenSubKey("Software\\Microsoft\\Office\\$intOffice.0\\Registration")){
			$regOfficeReg = $regLM.OpenSubKey("Software\\Microsoft\\Office\\$intOffice.0\\Registration")
			$colID = $regOfficeReg.GetSubKeyNames()
			foreach ($id in $colID){
				$regVer = $regLM.OpenSubKey("Software\\Microsoft\\Office\\$intOffice.0\\Registration\$id")
					if (($regVer.GetValue("ProductName") -like "*Office*" -and $regVer.GetValue("ProductName") -notlike "*Visio*" -and $regVer.GetValue("ProductName") -notlike "*Project*" -and $regVer.GetValue("ProductName") -notlike "*Access*")){
						[String]$strOffice = $regVer.GetValue("ProductName")
					}
					if ($regVer.GetValue("SPLevel")){
						[String]$strOfficeSP = $regVer.GetValue("SPLevel")
					}
			}
    	}
	}
    

    # Internet Explorer Version
    $regIE = $regLM.OpenSubKey("SOFTWARE\\Microsoft\\Internet Explorer")
    
    
	#Create Object containing results
	$objSystemInfo | Add-Member NoteProperty Name $wmiComputerSystem.Name
	if ($strComputer -eq '.' -and $wmiComputerSystem.Name ){ $strComputer = $wmiComputerSystem.Name }
	$objSystemInfo | Add-Member NoteProperty Model $wmiComputerSystem.Model
	$objSystemInfo | Add-Member NoteProperty BIOS $wmiBios.SMBIOSBIOSVersion
	$objSystemInfo | Add-Member NoteProperty Serial $wmiBios.serialnumber
	
	#Dell Warranty
	Write-Progress -Activity "Creating Report"  -Status "Collecting System Information" -CurrentOperation "Getting Warranty"
	
	$warranty = Get-DellWarranty -ServiceTag "$($wmiBios.serialnumber)"
	
	if ($warranty){
		$objSystemInfo | Add-Member NoteProperty WarrantyEnd $($warranty.EndDate.ToShortDateString())
	}

	Write-Progress -Activity "Creating Report"  -Status "Collecting System Information" -CurrentOperation "Getting Memory"
	[int]$memoryTotal = ([math]::round($wmiComputerSystem.TotalPhysicalMemory/1MB,0))
	[int]$memoryUsed = [Math]::Round(($wmiComputerSystem.TotalPhysicalMemory/1MB) - $wmiPerfOSMemory.availablembytes,0)
	[int]$memoryPercent = ($memoryUsed/$memoryTotal) * 100
	
	[String]$strAvailableMemory = $memoryUsed
	$strAvailableMemory += 'MB /'
	$strAvailableMemory += $memoryTotal
	$strAvailableMemory += 'MB'
	$strAvailableMemory += " [$memoryPercent%]"
	$strCPU = "$($wmiCPU.Name) $($wmiCPU.DataWidth)bit x $($wmiComputerSystem.NumberOfProcessors)"
	
	$objSystemInfo | Add-Member NoteProperty CPU $strCPU
	$objSystemInfo | Add-Member NoteProperty LogicalCPUs $wmiComputerSystem.NumberOfLogicalProcessors
	$objSystemInfo | Add-Member NoteProperty CPUUsage "$(($wmiCPU | Measure-Object -property LoadPercentage -Average).Average)%"
	$objSystemInfo | Add-Member NoteProperty Memory $strAvailableMemory
	if ($wmiOS | Get-Member -type Property | ?{ $_.Name -eq 'OSArchitecture' }){
		$strOS = $wmiOS.Caption + " " + $wmiOS.OSArchitecture
	} Else {
		$strOS = $wmiOS.Caption
	}
	$objSystemInfo | Add-Member NoteProperty OS $strOS
	$objSystemInfo | Add-Member NoteProperty SP $wmiOS.CSDVersion
	$objSystemInfo | Add-Member NoteProperty IE $regIE.getValue("Version")
	$objSystemInfo | Add-Member NoteProperty "Office" ($intOffice + " - " + $strOffice + " " + $strOfficeSP)
	if ($wmiComputerSystem.Username){ $objSystemInfo | Add-Member NoteProperty CurrentUser $wmiComputerSystem.Username }
	$lastUser = ($regLM.OpenSubKey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon")).GetValue("DefaultUserName")
	$objSystemInfo | Add-Member NoteProperty LastUser $lastUser
	try {
		if ($wmiOS.InstallDate){
			$objSystemInfo | Add-Member NoteProperty InstallDate $(([WMI]'').ConvertToDateTime($wmiOS.InstallDate) )
		}
	} Catch {}
	try {
		if ($wmiOS.LastBootUpTime){
			[DateTime]$lastBoot = $wmiOS.ConvertToDateTime($wmiOS.LastBootUpTime)
		}
	} Catch {}
	try {
		$upTime = New-TimeSpan -seconds $wmiPerfOsSystem.SystemUpTime -ErrorAction SilentlyContinue 
	} Catch {}
	[String]$strUptime = $uptime
	if ($lastBoot){
		 $strUptime = "$strUptime [$lastBoot]"
	}
	$objSystemInfo | Add-Member NoteProperty Uptime "$strUptime"
	
	Write-Object "SystemInformation" $objSystemInfo "List"
	#EndRegion
	
	#Region Remote Sessions
	#Requires PSTerminal Services http://code.msdn.microsoft.com/PSTerminalServices
	Write-Progress -Activity "Creating Report"  -Status "Remote Sessions" -CurrentOperation "Please Wait"
	$ts = $null
	if ((Get-Module | ForEach-Object {$_.Name}) -EQ "PSTerminalServices" ){
		if ($regLM.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Terminal Server")){
			$regTS = $regLM.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Terminal Server",$true) 
			$regTS.SetValue('AllowRemoteRPC','1','DWORD')
		}
		
		Try{ $ts = Get-TSSession -errorAction continue -ComputerName $strComputer}
		Catch{}
		if ($ts){	
			$objTS = $ts | Where-Object { $_.State -ne "Listening" -and $_.WindowStationName -ne "Services" } | Select-Object WindowStationName,UserAccount,ClientName,ConnectionState,ConnectTime,DisconnectTime,LoginTime,IdleTime 
			if ($objTS){ Write-Object "RemoteDesktopSessions" $objTS "List" }
		}
	}
	#EndRegion
	#Region LocalProfiles
	Write-Progress -Activity "Creating Report"  -Status "Local Profiles" -CurrentOperation "Please Wait"
	$objProfiles = Get-UserProfiles -ComputerName $strComputer | Select LocalPath,LastUseTime
	if ($objProfiles){ Write-Object "LocalProfiles" $objProfiles "Table" }
	#EndRegion
	
	#Region Network Info
	Write-Progress -Activity "Creating Report"  -Status "Network" -CurrentOperation "Please Wait"
    $objNet =  $wmiNet | Where-Object {$_.IPEnabled -EQ "True" -AND $_.IPAddress -AND $_.IPAddress -NOTMATCH "0.0.0.0"} | Sort-Object -Unique IPAddress | Select-Object -Unique -Property Description,MACAddress,DNSDomain,@{Name="IPAddress";Expression={[System.String]::Join(", ",$_.IPAddress)}},@{Name="IPSubnet";Expression={[System.String]::Join(", ",$_.IPSubnet)}},@{Name="IPGateway";Expression={[System.String]::Join(", ",$_.DefaultIPGateway)}},DHCPServer,@{Name="DHCPLeaseObtained"; Expression={$wmiOS.ConvertToDateTime($_.DHCPLeaseObtained)}},@{Name="DHCPLeaseExpires"; Expression={$wmiOS.ConvertToDateTime($_.DHCPLeaseExpires)}},@{Name="DNSServerSearchOrder";Expression={[System.String]::Join(", ",$_.DNSServerSearchOrder)}},@{Name="DNSDomainSuffixSearchOrder";Expression={[System.String]::Join(", ",$_.DNSDomainSuffixSearchOrder)}}
	Write-Object "NetworkConnections" $objNet "List"
	#EndRegion
	
	#Region Printers
	Write-Progress -Activity "Creating Report"  -Status "Printers" -CurrentOperation "Please Wait"
	$wmiPrinters = Get-WmiObject -ComputerName $strComputer Win32_Printer -ErrorAction SilentlyContinue | Select-Object Name,Comment
	if ($wmiPrinters){ Write-Object "Printers" $wmiPrinters "Table" }
	#EndRegion
	
	#Region Hosts file
	Write-Progress -Activity "Creating Report"  -Status "Hosts File" -CurrentOperation "Please Wait"
	$objHosts = @()
	try {
		$regWinNT = $regLM.OpenSubKey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion")
	} Catch {}
	if ( $regWinNT ){
		$strWinDir = $regWinNT.GetValue("PathName")
		$strHosts = "\\" + $strComputer + "\" + $strWinDir.Replace(":","$") + "\System32\Drivers\etc\hosts"
		if (Test-Path $strHosts){
			$hostsFile = Get-Content $strHosts | Where-Object {-not $_.StartsWith("#") -and $_.length -gt 0 -and $_ -ne "127.0.0.1       localhost" -and $_ -ne "::1             localhost" -and $_}	
			foreach ($s in $hostsFile){
				$hostEntry = New-Object PSCustomObject
				$hostEntry | Add-Member NoteProperty Entry $s
				$objHosts += $hostEntry
			}
		}
		if ($objHosts.length -gt 1){ Write-Object "HostsFile" $objHosts "Table" }
	}
	#EndRegion
	
    #Region Local Disks
	Write-Progress -Activity "Creating Report"  -Status "Collecting Hard Drive Information" -CurrentOperation "Please Wait"
    $wmiDisks = Get-WmiObject -query "SELECT Caption,VolumeName,Size,Freespace FROM win32_logicaldisk WHERE DriveType=3" -computer $strComputer | Select-Object Caption,VolumeName,@{Name="Size(GB)"; Expression={"{0:N2}" -f ($_.Size/1GB)}},@{Name="Freespace(GB)"; Expression={"{0:N2}" -f ($_.Freespace/1GB)}}, @{n="% Free";e={"{0:P2}" -f ([long]$_.FreeSpace/[long]$_.Size)}} | Sort-Object "Caption"
	Write-Object "Disk" $wmiDisks "List"
	#EndRegion
	
	#Region Mapped Drives
	Write-Progress -Activity "Creating Report"  -Status "Collecting Mapped Drives" -CurrentOperation "Please Wait"
	$networkDrives = Get-WmiObject -ComputerName $strComputer Win32_MappedLogicalDisk -ErrorAction SilentlyContinue | Select Name,ProviderName
	if (!($networkDrives)){
		#Get Directly from registry
		try{
			$userSids = $regUsers.GetSubKeyNames() | ?{ $_ -like "S-1-5-21-*" -and $_ -notlike "*_Classes" }
			foreach ($SID in $userSids){
				$networkDrives = @()
				#Get User's profile for results
				try{
					$profilePath = $null
					$profilePath = ($regLM.OpenSubKey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\$sid")).GetValue('ProfileImagePath')
				} Catch {}
				if ($profilePath){
					$itemUser = $profilePath.Substring($profilePath.LastIndexOf('\')+1)
				}
			
				$regUser = $regUsers.OpenSubkey($sid)
				$regNet = $regUser.OpenSubKey('Network')
			
				if ($regNet){
					foreach ($k in $regNet.GetSubKeyNames()){
						$item = '' | Select Name,ProviderName
						$item.Name = "$k" + ":"
						$item.ProviderName = $regNet.OpenSubKey($k).GetValue('RemotePath')
						$networkDrives += $item
					}
				}
			
			}
		} Catch { 
			#Failed to get Network Drives
		}
	} 
	Write-Object "NetworkDrives" $networkDrives "Table"
	#EndRegion
	
    #Region Minidump Files
    [int]$intDays = 30
	$regWinNT = $regLM.OpenSubKey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion")
	$strWinDir = $regWinNT.GetValue("PathName")
	$strMiniDump = "\\" + $strComputer + "\" + $strWinDir.Replace(":","$") + "\Minidump"
    IF (Test-Path $strMiniDump){
        $mini = Get-ChildItem $strMiniDump | Select-Object Name,LastWriteTime | Where-Object { ($(get-date) - $_.lastwritetime).days -LE $intDays} |Sort-Object LastWriteTime -Descending
		if ($mini){ Write-Object "Minidumps" $mini "Table" }
    }
    #EndRegion
	
    #Region Processes
	$objProcess = Get-ProcessTree -ComputerName $strComputer
	$intProc = $objProcess.length
	Write-Object "Process" $objProcess "Table" 
	#EndRegion
	
    #Region Startup Items
	Write-Progress -Activity "Creating Report" -Status "Collecting Startup Items" -CurrentOperation "Please Wait"
	$objStartup = @()
    $regLMKey = $regLM.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Run")
    foreach ($val in $regLMKey.GetValueNames()) {
        if ($val){
            $objStartupItem = New-Object PSCustomObject
			[String]$strValue = $regLMKey.GetValue($val)
			Write-Progress -Activity "Creating Report" -Status "Collecting Startup Items" -CurrentOperation $strValue
			$objStartupItem | Add-Member NoteProperty Name $val 
			$objStartupItem | Add-Member NoteProperty Value $strValue
			$objStartup += $objStartupItem
        }
    }
	$objStartup = $objStartup | Sort-Object Name
	if ($objStartup){ Write-Object "Startup" $objStartup "Table" }
	
	#64bit startup
	$objStartup64 = @()
    $strRun64 = "Software\\Wow6432Node\Microsoft\\Windows\\CurrentVersion\\Run"
    if ($regLM.OpenSubKey($strRun64)){ 
        $regStartup64 = $regLM.OpenSubKey($strRun64) 
        foreach ($val in $regStartup64.GetValueNames()) {
            if ($val){
				$objStartupItem64 = New-Object PSCustomObject
				[String]$strValue64 = $regStartup64.GetValue($val)
				Write-Progress -Activity "Creating Report" -Status "Collecting Startup Items" -CurrentOperation $strValue
				$objStartupItem64 | Add-Member NoteProperty Name $val 
				$objStartupItem64 | Add-Member NoteProperty Value $strValue64
				$objStartup64 += $objStartupItem64
            }   
        }
		$objStartup64 = $objStartup64 | Sort-Object Name
		Write-Object "Startup64" $objStartup64 "Table"
	}
    	
	
	
    #User Startup Items
    if ($regUsers){
		$regUsers.GetSubKeyNames() | Where {$_ -AND $_ -NE "S-1-5-18" -AND $_ -NE "S-1-5-19" -AND $_ -NE "S-1-5-20" -AND $_ -NOTLIKE "S-1-5-21-*-500" -AND $_ -NE ".DEFAULT" -AND $_ -NOTLIKE "*_Classes"} | %{ 
			$objUserRun = @()
			try {
				$regProfiles = $regLM.OpenSubKey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\$_")
				$strUser = $regProfiles.GetValue("ProfileImagePath")
				$strUser = $strUser.Substring($strUser.LastIndexOf('\')+1)
				if ($regUsers.OpenSubKey("$_\\Software\\Microsoft\Windows\\CurrentVersion\\Run")) { 
					$regUsersKey = $regUsers.OpenSubKey("$_\\Software\\Microsoft\Windows\\CurrentVersion\\Run")
					if ($regUsersKey.GetValueNames()){
						ForEach ($val in $regUsersKey.GetValueNames()) {
								$objUserItem = New-Object PSCustomObject
								$value = $val
								$strValue = $regUsersKey.GetValue($val)
								Write-Progress -Activity "Creating Report" -Status "Collecting Startup Items" -CurrentOperation "Please Wait"
								$objUserItem | Add-Member NoteProperty Name $val 
								$objUserItem | Add-Member NoteProperty Value $strValue
								$objUserRun += $objUserItem
						}
						Write-Object "Startup-$strUser" $objUserRun "Table"						
					}
				} 
			} Catch {}
	    }
	}	
	#EndRegion
	#Region BHO
$objBHOList = @()
If ($regLM.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects")){
	$regLMKey = $regLM.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects")
		foreach ($bho in $regLMKey.GetSubKeyNames()){
			$objBHO = New-Object PSCustomObject
			$bhoKey = $regLM.OpenSubKey("SOFTWARE\Classes\CLSID\$bho\InprocServer32")
			if ($bhoKey){
				$BHOValue = $bhoKey.GetValue("")
				Write-Progress -Activity "Creating Report" -Status "Collecting BHO Items" -CurrentOperation $BHOValue
				$objBHO | Add-Member NoteProperty ID $bho
				$objBHO | Add-Member NoteProperty Value $BHOValue
				$objBHOList += $objBHO
			}
		}
		if ($objBHOList){ Write-Object "BHO" $objBHOList "Table" }
}
	#EndRegion
#Region Winlogon items
#AppInit_DLLs
$objWinlogon = @()
if ($regLM.OpenSubKey("SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify")){ $regLMKey = $regLM.OpenSubKey("SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify") }
$strAppInit = $null
if ($regLMKey.GetValue("AppInit_DLLs")){ $strAppInit = $regLMKey.GetValue("AppInit_DLLs") }
if ($strAppInit){
	$objAppInit = New-Object PSCustomObject
	$objAppInit | Add-Member Noteproperty Name "AppInit"
	$objAppInit | Add-Member Noteproperty Value $strAppInit
	$objWinlogon += $objAppInit
    }


#Userinit
$regLMKey = $regLM.OpenSubKey("SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon")
$strUserinit = $regLMKey.GetValue("Userinit")
if ($strUserinit -NE "C:\WINDOWS\system32\userinit.exe," -AND $strUserinit -NE "C:\WINDOWS\system32\userinit.exe"){
	$objUserinit = New-Object PSCustomObject
	$objUserinit | Add-Member Noteproperty Name "UserInit"
	$objUserinit | Add-Member Noteproperty Value $strUserinit
	$objWinlogon += $objUserinit
}

#Shell
$strShell = $regLMKey.GetValue("Shell")
if ($strShell -ne "explorer.exe"){
	$objShell = New-Object PSCustomObject
	$objShell | Add-Member NoteProperty Name "Shell"
	$objShell | Add-Member NoteProperty Value $strShell
	$objWinlogon += $objShell
}


if ($objWinlogon){ Write-Object "Winlogon" $objWinLogon "Table" }
#EndRegion

#Region Services
if ($Services){
	Write-Progress -Activity "Creating Report"  -Status "Collecting Services" -CurrentOperation "Please Wait"
	$objServicesList = @()
	$systemDirectory = $wmiOS.WindowsDirectory
    Get-WmiObject win32_service -ComputerName $strComputer | ?{ $_ } | ForEach-Object {
        if ($_.PathName){
            [String]$strPathName = $_.PathName
            [Int]$intParamDash = $strPathName.indexOf(" -")
            if ($intParamDash -NE -1 ){$strPathName = $strPathName.remove($intParamDash)}
            [Int]$intParamSlash = $strPathName.indexOf(" /")
            if ($intParamSlash -NE -1 ){$strPathName = $strPathName.remove($intParamSlash)}
			if (!($strPathName.Contains('.'))){
				$strPathName = (Get-ChildItem $strPathName* | Select -First 1).FullName
			}
            $strPathName = $strPathName.Replace(":","$")
            $strRemPath = "\\" + $strComputer + "\" + $strPathName.Replace("`"","")
            
            if ($strRemPath -AND (Test-Path -Path $strRemPath -PathType Leaf)){
                #$objFileInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($strRemPath)
				$objFileInfo = (Get-Item $strRemPath).VersionInfo
			} Else { 
				$objFileInfo = ''| Select CompanyName
				$objFileInfo.CompanyName = "`(File not found`)"
			}
            if (!($_.PathName -like "$systemDirectory*" -or $_.PathName -like "`"$systemDirectory*" -and $objFileInfo.CompanyName -like "Microsoft*")){
				#if ($objFileInfo.CompanyName){ $strCompany = $objFileInfo.CompanyName } ELSE { $strCompany = "   `(None`)     " }
				#if ($strCompany.length -GE 20){ $strCompany = $strCompany.Substring(0,20)}
				If (!(Test-Path -Path $strRemPath -PathType Leaf)) { $strCompany = "`(File not Found`)" }
				$objService = New-Object PSCustomObject
				Write-Progress -Activity "Creating Report" -Status "Collecting Services" -CurrentOperation $_.PathName		
				$objService = '' | Select Name,Company,Path
				$objService.Company = $objFileInfo.CompanyName
				$objService.Name = $_.Name
				$objService.Path = $_.PathName
				$objServicesList += $objService                    
            } 
             
        }
  	}
	if ($objServicesList){ Write-Object "Services" $objServicesList "Table" }
}
	#EndRegion
#Region Mapped PST Files
Write-Progress -Activity "Creating Report"  -Status "Getting Mail Info" -CurrentOperation "Please Wait"
	$PST = @()
	$OST = @()
	$objPST = @()
	$sharedMB = @()
	$userSids = $regUsers.GetSubKeyNames() | ?{ $_ -like "S-1-5-21-*" -and $_ -notlike "*_Classes" }
	#Each user's SID under HKU
	foreach ($sid in $userSids){
		#Get User's profile for results
		try{
			$profilePath = $null
			$profilePath = ($regLM.OpenSubKey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\$sid")).GetValue('ProfileImagePath')
		} Catch {}
		if ($profilePath){
			$itemUser = $profilePath.Substring($profilePath.LastIndexOf('\')+1)
		}
		
		$regUser = $regUsers.OpenSubkey($sid)
		$regWMS = $regUser.OpenSubKey('Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles')
		#Each Mail Profile
		if ($regWMS){
			foreach ($strProfile in $regWMS.GetSubKeyNames() | ?{ $_ }){
				$itemProfile = $strProfile
				$regProfile = $regWMS.OpenSubKey($strProfile)
				#Each Key in the profile
				foreach ($key in $regProfile.getSubkeyNames()){
					$regKey = $regProfile.OpenSubKey($key)
					$PSTBinaryData = $regKey.GetValue('001f6700')
					if ($PSTBinaryData){
						#Convert Binary data to string and add to results
						$item = '' | Select User,Profile,PST
						$item.User = $itemUser
						$item.Profile = $itemProfile
						$item.pst = [Text.Encoding]::Unicode.getString($PSTBinaryData)
						$objPST += $item
					}
				}
			}
		}
	}
	if ($objPST){
		Write-Object "PST" $objPST "Table"
	}
	#EndRegion
	
	#Region Programs
	if ($Programs){
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
					$objProgram = '' | Select Program,Version
					$objProgram.Program = $strProg
					$objProgram.Version = $regLMKey.OpenSubKey($sub).GetValue("DisplayVersion")
					if (!($objPrograms | ?{ $_.Program -eq $objProgram.Program -and $_.Version -eq $objProgram.Version })){
						#If its not already in the results, add it.
						$objPrograms += $objProgram
					}
				}
			}
		}
		$objPrograms = $objPrograms | Sort Program
		if ($objPrograms){ Write-Object "Programs" $objPrograms "Table" }
	}
	#EndRegion
	
	#Region HotFixes
	if ($HotFixes)
	{
		$objHotfixes = Get-HotfixDetails -Computer $strComputer | Sort InstalledOn -Descending
		if ($objHotfixes){ Write-Object ' HotFixes' $objHotfixes "Table" }
	}
	#Endregion
	
	#Region EventLog
	if ($EventLog){
		if ($wmiOS.version -ge 6)
		{
			$objEventApplication = Get-WinEventCustom -Computer $strComputer -logName 'Application'
			$objEventSystem = Get-WinEventCustom -Computer $strComputer -logName 'System'
		} else {
			$objEventApplication = Get-EventLogCustom -Computer $strComputer -logName 'Application'
			$objEventSystem = Get-EventLogCustom -Computer $strComputer -logName 'System'
			
		}
		Write-Object 'ApplicationEventLog' $objEventApplication "Table"
		Write-Object 'SystemEventLog' $objEventSystem "Table"
		
	}
	
	#EndRegion
	
	if ($PassThru) { 
		$objResults | Add-Member -Name 'Refresh' -MemberType ScriptMethod -Value { Get-Info $this.SystemInformation.Name -PassThru }
		$objResults 
	}
	else
	{
		. $htmlFileName
	}
}