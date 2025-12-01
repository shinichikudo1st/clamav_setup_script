# remove_file.ps1
# Removes and deletes a quarantine file in the quarantine directory.
# This script is triggered by Wazuh Active Response when rule 180601 fires.

$LOG_FILE = "C:\Program Files (x86)\ossec-agent\logs\remove_file.log"

# Helper function to log messages
function Write-Log {
    param([string]$Message)

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$timestamp] $Message"
    $dir = Split-Path $LOG_FILE -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }

    $fs = New-Object System.IO.FileStream(
        $LOG_FILE,
        [System.IO.FileMode]::Append,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::ReadWrite
    )
    $writer = New-Object System.IO.StreamWriter($fs)
    $writer.WriteLine($line)
    $writer.Flush()
    $writer.Dispose()
    $fs.Dispose()
}

# Read JSON alert from Wazuh stdin
try {
    $INPUT_JSON = [Console]::In.ReadLine()
    
    # Uncomment the line below for debugging if needed
    # Write-Log "[DEBUG] Input received: $INPUT_JSON"
} catch {
    Write-Log "[ERROR] Failed to read input from stdin"
    exit 1
}

try {
    $alertData = $INPUT_JSON | ConvertFrom-Json
    
    # Extract paths from the 'data' field of the alert (from custom JSON log)
    $QuarantinePath = $alertData.parameters.alert.data.quarantine_path
    $OriginalPath = $alertData.parameters.alert.data.file_path
    $WorkflowID = $alertData.parameters.alert.data.workflow_id
    $AgentName = $alertData.parameters.alert.data.agent_name
    $AgentID = $alertData.parameters.alert.data.agent_id
    $EventType = $alertData.parameters.alert.data.event_type
    
    if ([string]::IsNullOrEmpty($QuarantinePath) -or [string]::IsNullOrEmpty($OriginalPath)) {
        Write-Log "[ERROR] Missing path info. Quarantine: '$QuarantinePath', Original: '$OriginalPath'"
        exit 1
    }
    
    Write-Log "[INFO] Request to restore '$QuarantinePath' -> '$OriginalPath'"

} catch {
    Write-Log "[ERROR] Failed to parse alert JSON: $_"
    exit 1
}

# Check if the quarantined file actually exists
if (-not (Test-Path $QuarantinePath.enc)) {
    Write-Log "[ERROR] Quarantined file not found at: $QuarantinePath"
    exit 1
}

# Remove/delete the file
try {

    $Encrypted = "$QuarantinePath.enc"

    if (Test-Path $Encrypted) {
	Remove-Item $Encrypted -Force
	Write-Log "[SUCCESS] File deleted successfully: $OriginalPath | $QuarantinePath | $WorkflowID | $AgentName | $AgentID | $EventType"
    } else {
	Write-Log "[WARN] Quarantine file not found: $QuarantinePath"
    }
} catch {
    Write-Log "[ERROR] Failed to delete file: $_"
    exit 1
}