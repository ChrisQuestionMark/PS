function Test-Credential {
    <#
    .SYNOPSIS
        Takes a PSCredential object and validates it against the domain (or local machine, or ADAM instance).

    .PARAMETER cred
        A PScredential object with the username/password you wish to test. Typically this is generated using the Get-Credential cmdlet. Accepts pipeline input.

    .PARAMETER context
        An optional parameter specifying what type of credential this is. Possible values are 'Domain','Machine',and 'ApplicationDirectory.' The default is 'Domain.'

    .OUTPUTS
        A boolean, indicating whether the credentials were successfully validated.

    #>
    param(
        [parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [System.Management.Automation.PSCredential]$credential,
        [parameter()][validateset('Domain','Machine','ApplicationDirectory')]
        [string]$context = 'Domain'
    )
    begin {
        Add-Type -assemblyname system.DirectoryServices.accountmanagement
        $DS = New-Object System.DirectoryServices.AccountManagement.PrincipalContext($context) 
    }
    process {
        $DS.ValidateCredentials($credential.UserName, $credential.GetNetworkCredential().password)
    }
}

Function Get-PSExec{
	param
	(
		$httpPath = 'http://live.sysinternals.com/psexec.exe',
		$smbPath,
		$dest = $ENV:Windir
	)
	
	try {
		$test = Start-Process -PassThru -FilePath 'psexec.exe' -ArgumentList '-accepteula -?' -WindowStyle Hidden
	} Catch {
		if (Test-Path $smbPath){
			Copy-Item $smbPath $dest
		} Else {
			$wc = New-Object System.Net.WebClient
			$wc.DownloadFile( $httpPath, "$dest\psexec.exe" )
		}
	}
}

Function Start-PSExec {
	param(
		[String]$Computer,
		[String]$psCommand,
		[Switch]$copy,
		[Switch]$noWait,
		[Switch]$system,
		[System.Management.Automation.PSCredential]$Credential
	)
	[int]$timeout = 20
	Get-PSExec
	$psexecEXE = 'psexec.exe'
	
	if ($Computer){
		[String]$startParam="\\$Computer -h"
	} else {
		[String]$startParam="-h"
	}
	if ($copy){ $startParam += ' -c -f' }
	if ($noWait){ $startParam += ' -d' }
	if ($system) { $startParam += ' -s -i ' }
	if ($credential){
		if (!(Test-Credential $credential)){
			Return "Invalid Credentials"
		}
		$startParam += " -u $($cred.UserName) -p $($cred.GetNetworkCredential().Password)"
	
	}
	$startParam += " $psCommand"
	#Write-Host $startParam
	
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
	
	if ($noWait){
		#Wait for process to start to get Proc ID
		$counter = 1
		while ($p.HasExited -eq $false -and $counter -le $timeout){
			Start-Sleep -Seconds 1	
			$counter++
		}
		
		#Return ProcID or error
		$output = $p.StandardError.ReadToEnd()
		#return $output
		$a = $output
		$b = $a.Split('.') | ?{ $_ -like '*process ID*' }
		if ($b){
			[int]$ID = $b.Split(' ') | Select -Last 1
			$ID
		} Else {
			$o = $output.Split("`r") | %{ $_.Trim() } | ?{ $_ }
			if ($o -and $o.Length -ge 4){
				$o[3]
			}
		}
	} Else {
		Write-Progress -Activity "$psCommand on $Computer" -Status "Waiting for process to exit"
		$p.WaitForExit()
		$output = $p.StandardOutput.ReadToEnd()
		#Write-Host $p.StandardError.ReadToEnd()
		return $output
	}
}