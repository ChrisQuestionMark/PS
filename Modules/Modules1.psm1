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
	
	
	