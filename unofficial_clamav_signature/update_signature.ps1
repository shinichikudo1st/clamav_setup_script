# ================================
# Windows Fangfrisch Alternative
# ClamAV Third-Party Signature Updater
# ================================

$ClamDB = "C:\Program Files\ClamAV\database"
$SigDir = "C:\Program Files\ClamAV\thirdparty-signatures"
$LogFile = "C:\Program Files\ClamAV\sig_update.log"

# Ensure modern TLS and set a browser-like User-Agent for providers that block generic scripts
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$DownloadHeaders = @{ "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" }

# Create directories if missing
New-Item -ItemType Directory -Force -Path $SigDir | Out-Null

function Log {
    param([string]$msg)
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    Add-Content -Path $LogFile -Value "[$ts] $msg"
}

# Signature feeds
$Feedfile = "feeds.psd1"

if (Test-Path $Feedfile) {
    $Feeds = Import-PowerShellDataFile -Path $FeedFile
} else {
    Write-Host "Feed config file missing! ($FeedFile)"
    exit 1
}

Write-Host "Starting 3rd-party signature update..."

foreach ($name in $Feeds.Keys) {
    $Url = $Feeds[$name]
    $OutFile = Join-Path $SigDir ($name)

    try {
        Write-Host "Downloading: $Url"
        Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing -Headers $DownloadHeaders

        if (Test-Path $OutFile) {
            Write-Host "Downloaded successfully: $name"
        }
    } catch {
        Write-Host "ERROR downloading $Url - $_"
    }
}

# Copy updated signatures into ClamAV DB directory
Write-Host "Copying signature files into ClamAV directory..."

Get-ChildItem -Path $SigDir | ForEach-Object {
    Copy-Item -Path $_.FullName -Destination $ClamDB -Force
}

Write-Host "Signature update completed successfully."

#To run, paste powershell -ExecutionPolicy Bypass -File update_signature.ps1