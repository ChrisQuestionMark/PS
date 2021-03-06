#requires -version 2

Function Get-SQLData 
{
	param
	(
		[Parameter(ValueFromPipeline=$true,Mandatory=$true)] [ValidateNotNullOrEmpty()]
		[String]$connectionString,
		[Parameter(ValueFromPipeline=$true,Mandatory=$true)] [ValidateNotNullOrEmpty()]
		[String]$Query
	)
	
	$ConnectionTimeout = 10
	$QueryTimeout = 30
	$conn = new-object System.Data.SqlClient.SQLConnection
	$conn.ConnectionString=$ConnectionString
	$conn.Open()
	$cmd=new-object system.Data.SqlClient.SqlCommand($Query,$conn)
	$cmd.CommandTimeout=$QueryTimeout
	$ds=New-Object system.Data.DataSet
	$da=New-Object system.Data.SqlClient.SqlDataAdapter($cmd)
	[void]$da.fill($ds)
	$conn.Close()
	$ds.Tables | Select -ExpandProperty DefaultView
}