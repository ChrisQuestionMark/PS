
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
	
	
	