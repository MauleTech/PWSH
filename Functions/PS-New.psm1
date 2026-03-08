Function New-BPAResultObject {
	param(
		[psobject]$Finding,
		[psobject]$Model,
		[string]$ComputerName,
		[string]$Status,
		[string]$Target = $null,
		$PreviousValue = $null,
		$NewValue = $null,
		[string]$Reason = $null
	)
	return [PSCustomObject]@{
		Timestamp     = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
		ComputerName  = $ComputerName
		ModelId       = $Model.Id
		RuleId        = $Finding.RuleId
		Title         = $Finding.Title
		Category      = $Finding.Category
		Severity      = $Finding.Severity
		Target        = $Target
		Status        = $Status
		PreviousValue = $PreviousValue
		NewValue      = $NewValue
		Reason        = $Reason
	}
}
