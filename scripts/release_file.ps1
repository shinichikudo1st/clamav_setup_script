# release_file.ps1
# Restores a quarantined file to its original location based on Wazuh alert data.
# This script is triggered by Wazuh Active Response when rule 180501 fires.

# Configuration
$LOG_FILE = "C:\Program Files (x86)\ossec-agent\logs\release.log"
$WHITELIST_FILE = "C:\Program Files\ClamAV\whitelist.txt"

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

function Decrypt-File {
    param(
        [string]$EncryptedPath,
        [string]$OutPath,
        [string]$Password
    )

    $FileBytes = [IO.File]::ReadAllBytes($EncryptedPath)

    # Extract salt (first 16 bytes)
    $Salt = $FileBytes[0..15]
    $EncryptedBytes = $FileBytes[16..($FileBytes.Length - 1)]

    # Derive same key + IV using same salt
    $PBKDF2 = New-Object Security.Cryptography.Rfc2898DeriveBytes($Password, $Salt, 100000)
    $AES = [System.Security.Cryptography.Aes]::Create()
    $AES.Key = $PBKDF2.GetBytes(32)
    $AES.IV  = $PBKDF2.GetBytes(16)

    # Decrypt
    $Decryptor = $AES.CreateDecryptor()
    $DecryptedBytes = $Decryptor.TransformFinalBlock($EncryptedBytes, 0, $EncryptedBytes.Length)

    [IO.File]::WriteAllBytes($OutPath, $DecryptedBytes)
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

# Ensure destination directory exists
$DestDir = Split-Path -Path $OriginalPath -Parent
if (-not (Test-Path $DestDir)) {
    try {
        New-Item -ItemType Directory -Force -Path $DestDir | Out-Null
        Write-Log "[INFO] Created destination directory: $DestDir"
    } catch {
        Write-Log "[ERROR] Failed to create destination directory: $_"
        exit 1
    }
}

# Add to whitelist BEFORE moving to prevent race condition with FIM detection
try {
    # Format: "TIMESTAMP|FILEPATH"
    # We use a 5-minute window for the whitelist validity in the scan script
    $entry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$OriginalPath"
    Add-Content -Path $WHITELIST_FILE -Value $entry
    Write-Log "[INFO] Added to whitelist: $OriginalPath"
} catch {
    Write-Log "[WARN] Failed to update whitelist - loop might occur"
}

# Restore the file (Move it back)
try {
    $EncryptedPath = "$QuarantinePath.enc"
    $Password = "SUPER_SECRET_KEY"
    
    if (Test-Path $EncryptedPath) {
	Write-Log "Decrypting file..."
    	Decrypt-File -EncryptedPath $EncryptedPath -OutPath $OriginalPath -Password $Password

    	# remove encrypted quarantine file
    	Remove-Item $EncryptedPath -Force

    } elseif (Test-Path $QuarantinePath) {
        Move-Item -Path $QuarantinePath -Destination $OriginalPath -Force
    } else {
    	Write-Host "Error: No quarantined file found."
    }

    Write-Log "[SUCCESS] File restored successfully to: $OriginalPath | $QuarantinePath | $WorkflowID | $AgentName | $AgentID | $EventType"
} catch {
    Write-Log "[ERROR] Failed to move file: $_"
    exit 1
}

