# revert_file.ps1
# Reverts a restored file back to its quarantined location

$QUAR_DIR = "C:\Program Files (x86)\ossec-agent\quarantine"
$LOG_FILE = "C:\Program Files (x86)\ossec-agent\logs\revert.log"

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
    
    Write-Log "[INFO] Request to revert '$OriginalPath' -> '$QuarantinePath'"

} catch {
    Write-Log "[ERROR] Failed to parse alert JSON: $_"
    exit 1
}

# Ensure quarantine directory exists
if (-not (Test-Path $QUAR_DIR)) {
    try {
        New-Item -ItemType Directory -Force -Path $QUAR_DIR | Out-Null
        Write-Log "[WAZUH] Created quarantine directory: $QUAR_DIR"
    } catch {
        Write-Log "[WAZUH-ERROR] Failed to create quarantine directory: $_"
        exit 1
    }
}

# Encrypt quarantine file
$FileName = [IO.Path]::GetFileName($OriginalPath)
$QuarantinedPath = Join-Path $QUAR_DIR $FileName

if (Test-Path $QuarantinedPath) {
    $Encrypted = "$($QuarantinedPath).enc"
    $Password = "SUPER_SECRET_KEY"

    # Create salt
    $Salt = New-Object byte[] 16
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($Salt)

    $PBKDF2 = New-Object Security.Cryptography.Rfc2898DeriveBytes($Password, $Salt, 100000)
    $AES = [System.Security.Cryptography.Aes]::Create()
    $AES.Key = $PBKDF2.GetBytes(32)
    $AES.IV  = $PBKDF2.GetBytes(16)

    # Encrypt file
    $InputBytes = [IO.File]::ReadAllBytes($QuarantinedPath)
    $Encryptor  = $AES.CreateEncryptor()
    $EncryptedBytes = $Encryptor.TransformFinalBlock($InputBytes, 0, $InputBytes.Length)

    # Combine salt + encrypted data
    $Output = $Salt + $EncryptedBytes
    [IO.File]::WriteAllBytes($Encrypted, $Output)

    Write-log "Encrypted file: $QuarantinedPath"

    # Remove original infected file
    Remove-Item $QuarantinedPath -Force

    Write-Log "[SUCCESS] File reverted successfully: $OriginalPath | $QuarantinePath | $WorkflowID | $AgentName | $AgentID | $EventType"
}
