# ClamAV-Wazuh Setup Script for Windows
# Run as Administrator

# Configuration
$CLAMAV_INSTALLER_URL = "https://www.clamav.net/downloads/production/clamav-1.4.3.win.x64.msi"
$CLAMAV_INSTALLER = "C:\Users\$env:USERNAME\Downloads\clamav-1.4.3.win.x64.msi"
$CLAMAV_DIR = "C:\Program Files\ClamAV"
$WAZUH_DIR = "C:\Program Files (x86)\ossec-agent"
$AR_BIN_DIR = "$WAZUH_DIR\active-response\bin"
$WAZUH_LOGS_DIR = "$WAZUH_DIR\logs"

Write-Host "[INFO] Starting ClamAV-Wazuh Integration Setup..." -ForegroundColor Green

# Download the installer
Invoke-WebRequest -Uri $CLAMAV_INSTALLER_URL -OutFile $CLAMAV_INSTALLER

if (Test-Path $CLAMAV_INSTALLER) {
    Start-Process msiexec.exe -ArgumentList "/i `"$CLAMAV_INSTALLER`" /quiet /norestart" -Wait
    Write-Host "[SUCCESS] ClamAV installed" -ForegroundColor Green
} else {
    Write-Host "[ERROR] ClamAV installer not found: $CLAMAV_INSTALLER" -ForegroundColor Red
    exit 1
}

# Wait for installation to complete
Start-Sleep -Seconds 5

# Step 2: Copy configuration files
Write-Host "[2/6] Configuring ClamAV..." -ForegroundColor Cyan
if (Test-Path "$CLAMAV_DIR\conf_examples") {
    Copy-Item "$CLAMAV_DIR\conf_examples\freshclam.conf.sample" "$CLAMAV_DIR\freshclam.conf" -Force
    Copy-Item "$CLAMAV_DIR\conf_examples\clamd.conf.sample" "$CLAMAV_DIR\clamd.conf" -Force
    
    # Remove "Example" line from freshclam.conf
    $freshclamContent = Get-Content "$CLAMAV_DIR\freshclam.conf"
    $freshclamContent | Where-Object { $_ -notmatch "^Example$" } | Set-Content "$CLAMAV_DIR\freshclam.conf"
    
    # Uncomment required lines in freshclam.conf
    (Get-Content "$CLAMAV_DIR\freshclam.conf") -replace '^#DatabaseDirectory', 'DatabaseDirectory' `
        -replace '^#UpdateLogFile', 'UpdateLogFile' | Set-Content "$CLAMAV_DIR\freshclam.conf"
    
    # Remove "Example" line from clamd.conf
    $clamdContent = Get-Content "$CLAMAV_DIR\clamd.conf"
    $clamdContent | Where-Object { $_ -notmatch "^Example$" } | Set-Content "$CLAMAV_DIR\clamd.conf"
    
    # Uncomment required lines in clamd.conf
    (Get-Content "$CLAMAV_DIR\clamd.conf") -replace '^#LogFile', 'LogFile' `
	-replace '^#LogFileUnlock', 'LogFileUnlock' `
        -replace '^#DatabaseDirectory', 'DatabaseDirectory' `
        -replace '^#TCPSocket', 'TCPSocket' `
        -replace '^#TCPAddr', 'TCPAddr' `
        -replace '^#LogTime yes', 'LogTime yes' `
        -replace '^#LogVerbose yes', 'LogVerbose yes' | Set-Content "$CLAMAV_DIR\clamd.conf"
    
    Write-Host "[SUCCESS] Configuration files created" -ForegroundColor Green
} else {
    Write-Host "[ERROR] ClamAV conf_examples directory not found" -ForegroundColor Red
    exit 1
}

# Create database directory
if (-not (Test-Path "$CLAMAV_DIR\database")) {
    New-Item -ItemType Directory -Path "$CLAMAV_DIR\database" -Force | Out-Null
}

# Step 3: Run freshclam to update virus definitions
Write-Host "[3/6] Updating virus definitions (this may take a few minutes)..." -ForegroundColor Cyan
try {
    & "$CLAMAV_DIR\freshclam.exe"
    Write-Host "[SUCCESS] Virus definitions updated" -ForegroundColor Green
} catch {
    Write-Host "[WARN] Freshclam update encountered issues: $_" -ForegroundColor Yellow
}

# Step 4: Create active response scripts
Write-Host "[4/6] Creating active response scripts..." -ForegroundColor Cyan

# Ensure active-response\bin directory exists
if (-not (Test-Path $AR_BIN_DIR)) {
    New-Item -ItemType Directory -Path $AR_BIN_DIR -Force | Out-Null
}

# Define source scripts directory (relative to this setup script)
$SCRIPT_SOURCE_DIR = "$PSScriptRoot\scripts"

# Copy PowerShell scripts from source directory
$scriptsToInstall = @(
    @{Source = "scan_new_file.ps1"; Wrapper = $true},
    @{Source = "release_file.ps1"; Wrapper = $true},
    @{Source = "remove_file.ps1"; Wrapper = $true},
    @{Source = "revert_file.ps1"; Wrapper = $true}
)

foreach ($script in $scriptsToInstall) {
    $sourcePath = "$SCRIPT_SOURCE_DIR\$($script.Source)"
    $destPath = "$AR_BIN_DIR\$($script.Source)"
    
    if (Test-Path $sourcePath) {
        Copy-Item $sourcePath $destPath -Force
        Write-Host "[SUCCESS] Installed: $($script.Source)" -ForegroundColor Green
        
        # Create .cmd wrapper if needed
        if ($script.Wrapper) {
            $cmdName = $script.Source -replace '\.ps1$', '.cmd'
            $cmdContent = @"
@echo off
PowerShell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp0$($script.Source)"
"@
            Set-Content -Path "$AR_BIN_DIR\$cmdName" -Value $cmdContent
            Write-Host "[SUCCESS] Created wrapper: $cmdName" -ForegroundColor Green
        }
    } else {
        Write-Host "[ERROR] Source script not found: $sourcePath" -ForegroundColor Red
        exit 1
    }
}

Write-Host "[SUCCESS] All scripts installed in $AR_BIN_DIR" -ForegroundColor Green

# Step 5: Update ossec.conf
Write-Host "[5/6] Updating Wazuh agent configuration..." -ForegroundColor Cyan

$ossecConfPath = "$WAZUH_DIR\ossec.conf"
$backupPath = "$WAZUH_DIR\ossec.conf.backup.$(Get-Date -Format 'yyyyMMdd_HHmmss')"

# Backup existing config
if (Test-Path $ossecConfPath) {
    Copy-Item $ossecConfPath $backupPath
    Write-Host "[INFO] Backup created: $backupPath" -ForegroundColor Yellow
} else {
    Write-Host "[ERROR] ossec.conf not found at: $ossecConfPath" -ForegroundColor Red
    exit 1
}

# Read existing config
[xml]$ossecXml = Get-Content $ossecConfPath

# Find the ossec_config node
$ossecConfig = $ossecXml.ossec_config

# Add localfile entries for ClamAV logs
$localfilesToAdd = @(
    @{Location = "C:\Program Files\ClamAV\freshclam.log"; Format = "syslog"},
    @{Location = "C:\Program Files\ClamAV\clamd.log"; Format = "syslog"},
    @{Location = "C:\Program Files\ClamAV\scan.log"; Format = "syslog"},
    @{Location = "C:\Program Files (x86)\ossec-agent\logs\release.log"; Format = "syslog"},
    @{Location = "C:\Program Files (x86)\ossec-agent\logs\remove_file.log"; Format = "syslog"},
    @{Location = "C:\Program Files (x86)\ossec-agent\logs\revert_file.log"; Format = "syslog"}
)

Write-Host "[INFO] Adding log file monitoring entries..." -ForegroundColor Cyan
foreach ($localfile in $localfilesToAdd) {
    # Check if already exists
    $exists = $ossecConfig.localfile | Where-Object { $_.location -eq $localfile.Location }
    if (-not $exists) {
        $newLocalfile = $ossecXml.CreateElement("localfile")
        
        $location = $ossecXml.CreateElement("location")
        $location.InnerText = $localfile.Location
        $newLocalfile.AppendChild($location) | Out-Null
        
        $logFormat = $ossecXml.CreateElement("log_format")
        $logFormat.InnerText = $localfile.Format
        $newLocalfile.AppendChild($logFormat) | Out-Null
        
        $ossecConfig.AppendChild($newLocalfile) | Out-Null
        Write-Host "  [+] Added: $($localfile.Location)" -ForegroundColor Green
    } else {
        Write-Host "  [EXISTS] $($localfile.Location)" -ForegroundColor Yellow
    }
}

# Add directories to syscheck
$directoriesToAdd = @(
    "C:\Users\Public",
    "C:\Users\Public\Downloads",
    "C:\Users\Public\Desktop",
    "C:\Users\*\Downloads",
    "C:\Temp"
)

Write-Host "[INFO] Adding real-time FIM monitoring directories..." -ForegroundColor Cyan
$syscheck = $ossecConfig.syscheck

foreach ($dir in $directoriesToAdd) {
    # Check if directory already monitored
    $exists = $syscheck.directories | Where-Object { $_.'#text' -eq $dir -or $_.InnerText -eq $dir }
    if (-not $exists) {
        $newDir = $ossecXml.CreateElement("directories")
        $newDir.SetAttribute("realtime", "yes")
        $newDir.InnerText = $dir
        $syscheck.AppendChild($newDir) | Out-Null
        Write-Host "  [+] Added: $dir" -ForegroundColor Green
    } else {
        Write-Host "  [EXISTS] $dir" -ForegroundColor Yellow
    }
}

# Save the modified XML
$ossecXml.Save($ossecConfPath)
Write-Host "[SUCCESS] Wazuh configuration updated" -ForegroundColor Green
Write-Host "[INFO] Config backup saved to: $backupPath" -ForegroundColor Yellow

# Step 6: Create log files
Write-Host "[6/6] Creating log files..." -ForegroundColor Cyan

# Create logs directory in active-response
$arLogsDir = "$WAZUH_DIR\logs"
if (-not (Test-Path $arLogsDir)) {
    New-Item -ItemType Directory -Path $arLogsDir -Force | Out-Null
}

# Create log files
$logFiles = @(
    "$arLogsDir\release.log",
    "$arLogsDir\remove_file.log",
    "$arLogsDir\revert_file.log",
    "$CLAMAV_DIR\scan.log",
    "$CLAMAV_DIR\clamd.log",
    "$CLAMAV_DIR\whitelist.txt"
)

foreach ($logFile in $logFiles) {
    if (-not (Test-Path $logFile)) {
        New-Item -ItemType File -Path $logFile -Force | Out-Null
        Write-Host "[SUCCESS] Created: $logFile" -ForegroundColor Green
    }
}

# Create quarantine directory
$quarantineDir = "$WAZUH_DIR\quarantine"
if (-not (Test-Path $quarantineDir)) {
    New-Item -ItemType Directory -Path $quarantineDir -Force | Out-Null
    Write-Host "[SUCCESS] Created quarantine directory: $quarantineDir" -ForegroundColor Green
}

# Step 7: Copy Unofficial Clamav Signature Directory to Public
# Write-Host "[7/7] Preparing unofficial signature bundle..." -ForegroundColor Cyan

# $signatureSource = Join-Path $PSScriptRoot "unofficial_clamav_signature"
# $signatureDest   = "C:\Users\$env:USERNAME\UnofficialClamAVSignature"

# if (-not (Test-Path $signatureSource)) {
#     Write-Host "[ERROR] Signature source folder not found: $signatureSource" -ForegroundColor Red
#     exit 1
# }

# Copy-Item $signatureSource $signatureDest -Recurse -Force
# Write-Host "[SUCCESS] Copied unofficial signatures to $signatureDest" -ForegroundColor Green

# # Apply ACLs (admins only on scripts, users RW on feeds)
# icacls "$signatureDest\update_signature.ps1" /inheritance:r /grant:r "Administrators:F" "SYSTEM:F" | Out-Null
# icacls "$signatureDest\signature_installer.ps1" /inheritance:r /grant:r "Administrators:F" "SYSTEM:F" | Out-Null
# icacls "$signatureDest\feeds.psd1" /inheritance:r /grant:r "Administrators:F" "SYSTEM:F" "Users:RW" | Out-Null
# Write-Host "[SUCCESS] Applied permission requirements" -ForegroundColor Green