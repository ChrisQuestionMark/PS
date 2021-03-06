Function Get-Clipboard {
	Add-Type -AssemblyName 'PresentationCore' | Out-Null
	return [Windows.Clipboard]::GetText() -replace "`r", '' -split "`n"
}

New-Alias  Out-Clipboard $env:SystemRoot\system32\clip.exe -ErrorAction SilentlyContinue

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
		$objects | ConvertTo-Csv -Delimiter "`t" -NoTypeInformation | Out-Clipboard 
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