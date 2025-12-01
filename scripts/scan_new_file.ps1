# scan_new_file.ps1
# Scans newly added or modified files reported by Wazuh syscheck

# Configuration
$QUAR_DIR = "C:\Program Files (x86)\ossec-agent\quarantine"
$CLAMSCAN = "C:\Program Files\ClamAV\clamscan.exe"
$LOG_FILE = "C:\Program Files\ClamAV\scan.log"
$WHITELIST_FILE = "C:\Program Files\ClamAV\whitelist.txt"

# Helper function to log messages
function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    try {
        Add-Content -Path $LOG_FILE -Value "[$timestamp] $Message"
    } catch {}
}

# Read JSON alert from Wazuh stdin
$INPUT_JSON = [Console]::In.ReadLine()
Write-Log "[WAZUH-DEBUG] Active response received: $INPUT_JSON"

# Extract file path from syscheck alert
$FilePath = $null
try {
    $alertData = $INPUT_JSON | ConvertFrom-Json
    $fullLog = $alertData.parameters.alert.full_log

    if ($fullLog -match "File\s+'([^']+)'\s+(added|modified)") {
        $FilePath = $matches[1]
        Write-Log "[WAZUH-DEBUG] Extracted file path: $FilePath"
    } else {
        Write-Log "[WAZUH-ERROR] Could not extract file path from full_log"
        exit 1
    }
} catch {
    Write-Log "[WAZUH-ERROR] Failed to parse alert JSON: $_"
    exit 1
}

# Check Whitelist
if (Test-Path $WHITELIST_FILE) {
    try {
        $entries = Get-Content $WHITELIST_FILE
        foreach ($line in $entries) {
            $parts = $line -split "\|"
            if ($parts.Length -eq 2) {
                $tsStr = $parts[0]
                $path = $parts[1]
                
                try {
                    $ts = [DateTime]::ParseExact($tsStr, "yyyy-MM-dd HH:mm:ss", $null)
                    
                    # Check if path matches AND it was whitelisted recently (last 5 mins)
                    if ($path -eq $FilePath -and (Get-Date).AddMinutes(-5) -lt $ts) {
                        Write-Log "[WAZUH-INFO] Skipping scan for recently released file: $FilePath"
                        exit 0
                    }
                } catch {
                    # Ignore parsing errors for old/bad lines
                }
            }
        }
    } catch {
        Write-Log "[WAZUH-WARN] Failed to read whitelist: $_"
    }
}

# Check if the file exists
if (-not (Test-Path $FilePath)) {
    Write-Log "[WAZUH-WARN] File does not exist: $FilePath"
    exit 0
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

# Scan the file with ClamScan and move if infected
try {
    & $CLAMSCAN --move="$QUAR_DIR" --log="$LOG_FILE" "$FilePath"
    Write-Log "[WAZUH-SUCCESS] Scanned and quarantined (if infected): $FilePath"
} catch {
    Write-Log "[WAZUH-ERROR] ClamScan failed on $FilePath - $_"
    exit 1
}

# Encrypt quarantine file
$LatestQuarantined = Get-ChildItem -Path $QUAR_DIR | Sort-Object LastWriteTime -Descending | Select-Object -First 1

if ($LatestQuarantined) {
    $Encrypted = "$($LatestQuarantined.FullName).enc"
    $Password = "SUPER_SECRET_KEY"

    # Create salt
    $Salt = New-Object byte[] 16
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($Salt)

    $PBKDF2 = New-Object Security.Cryptography.Rfc2898DeriveBytes($Password, $Salt, 100000)
    $AES = [System.Security.Cryptography.Aes]::Create()
    $AES.Key = $PBKDF2.GetBytes(32)
    $AES.IV  = $PBKDF2.GetBytes(16)

    # Encrypt file
    $InputBytes = [IO.File]::ReadAllBytes($LatestQuarantined.FullName)
    $Encryptor  = $AES.CreateEncryptor()
    $EncryptedBytes = $Encryptor.TransformFinalBlock($InputBytes, 0, $InputBytes.Length)

    # Combine salt + encrypted data
    $Output = $Salt + $EncryptedBytes
    [IO.File]::WriteAllBytes($Encrypted, $Output)

    Write-log "Encrypted file: $LatestQuarantined.FullName"

    # Remove original infected file
    Remove-Item $LatestQuarantined.FullName -Force
}
