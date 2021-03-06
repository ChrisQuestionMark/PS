Function Get-DellAssetInformation {
Param(
	[String[]]$ServiceTags = $(Get-WmiObject -Class "Win32_Bios").SerialNumber,
	[Switch]$asHashTable
	)
	$result = @()
	$hashResult = @{}
	$maxTags = 100
	if ($ServiceTags.length -gt $maxTags){
		#Break into smaller groups

		$computers = $ServiceTags
		$n = [Math]::Ceiling($($ServiceTags.length)/$maxTags)
		$complists = @{}
		$count = 0 
		$computers |% {
			$complists[$count % $n] += @($_)
			$count++
		} 
		$eCounter = 0
		$complists.GetEnumerator() | %{
			$eCounter++
			Write-Host "	Running job $eCounter of $($complists.count) ..." -NoNewline
			$subResult = Get-DellAssetInformation -ServiceTags $_.Value
			Write-Host " got $($subResult.length) results"
			$result += $subResult
		}
	} 
	Else
	{
		[String]$ServiceTag = $ServiceTags -join ','
		Try{
			$AssetService = New-WebServiceProxy -Uri "http://xserv.dell.com/services/AssetService.asmx?WSDL";
			$ApplicationName = "AssetService";
			$Guid = [Guid]::NewGuid();
			$Assets = $AssetService.GetAssetInformation($Guid,$ApplicationName,$ServiceTag);
			foreach ($Asset in $Assets)
			{
				$item = $Asset.AssetHeaderData | Select *,StartDate,EndDate,DaysLeft,EntitlementType
				$war = $Asset | Select -ExpandProperty Entitlements | Sort EndDate | Select -Last 1
				$item.StartDate = $war.StartDate
				$item.EndDate = $war.EndDate
				$item.DaysLeft = $war.DaysLeft
				$item.EntitlementType = $war.EntitlementType
				$result += $item
			}			
			
		}
		Catch 
		{
			Write-Host $($_.Exception.Message);	
		}
	}
	if ($asHashTable)
	{
		$result | %{ $hashResult.Add($_.ServiceTag,$_.EndDate) }
		return $hashResult
	}
	else
	{
		return $result
	}
}