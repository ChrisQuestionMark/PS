Function Get-Clipboard {
	Add-Type -AssemblyName 'PresentationCore' | Out-Null
	return [Windows.Clipboard]::GetText() -replace "`r", '' -split "`n"
}

Function Out-Clipboard {
	param(  
		[Parameter(mandatory=$true, ValueFromPipeline=$true)]$InputObject
	)
	begin
	{
		Add-Type -AssemblyName 'PresentationCore' | Out-Null
		$clipData = @()
	}
	process
	{
		$clipData += $InputObject + "`r"
	}
	end
	{
		[Windows.Clipboard]::SetText($clipData)
	}

}

Function Out-Excel {
  param(  
		[Parameter(mandatory=$true, ValueFromPipeline=$true)]$InputObject
    )
	begin { 
		$objects = @()
		$oldClip = Get-Clipboard
		
	}
    process { 
		$objects += $InputObject
	}
    end {
		$csv = $objects | ConvertTo-Csv -Delimiter "`t" -NoTypeInformation
		$csv | Out-Clipboard
		$excel = New-Object -ComObject Excel.Application -ErrorAction SilentlyContinue
		if ($excel){
			$excel.visible = $true
			$workbook = $excel.Workbooks.Add()
			$range = $workbook.ActiveSheet.Range("a1")
			$workbook.ActiveSheet.Paste($range, $false)
		} Else {
			Write-Error "Failed to start Excel"
		}
		if ($oldClip){
			$oldClip | Out-Clipboard
		}
	}
}