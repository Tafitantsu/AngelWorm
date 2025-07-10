# SRE.ps1 - Educational Worm Simulation Script

**🔴 IMPORTANT WARNING 🔴**

This script is designed **exclusively for educational purposes in isolated and controlled cybersecurity lab environments (e.g., VirtualBox, VMware)**. It simulates basic worm-like behavior for learning and training.

**DO NOT use this script in production, live, or any unauthorized networks. Unauthorized use of such tools is illegal and unethical. The author and contributors are not responsible for any misuse or damage caused by this script.**

## Table of Contents
1. [Purpose](#purpose)
2. [How It Works](#how-it-works)
   - [Network Scan](#network-scan)
   - [Infection Logic](#infection-logic)
   - [Propagation Rules](#propagation-rules)
   - [Persistence](#persistence)
3. [Script Structure](#script-structure)
   - [Configuration Variables](#configuration-variables)
   - [Key Functions](#key-functions)
4. [Lab Setup and Usage](#lab-setup-and-usage)
   - [Prerequisites](#prerequisites)
   - [Configuration Steps](#configuration-steps)
   - [Running the Script](#running-the-script)
5. [Limitations](#limitations)
6. [Disclaimer](#disclaimer)

## 1. Purpose
The `SRE.ps1` (Simulated Replication Engine) script is a PowerShell tool created to simulate the behavior of a network worm. Its primary goal is to provide a practical learning experience in a cybersecurity lab setting, allowing students and researchers to understand:
- Basic network scanning techniques.
- Remote payload deployment and execution.
- Lateral movement concepts within a network.
- Simple persistence mechanisms.
- The importance of network segmentation and security hygiene.

This script is **not** designed to be malicious. It does **not** include features like data encryption (ransomware), data exfiltration, or advanced evasion techniques.

## 2. How It Works

### Network Scan
- The script iterates through a predefined IP address range (default: `192.168.56.1` to `192.168.56.254`).
- For each IP address, it attempts to check if port `445` (SMB - Server Message Block) is open. This is a common port used for file sharing in Windows environments and is often targeted for lateral movement.

### Infection Logic
If a remote machine is found with port `445` open and is accessible:
1.  **Payload Copy**: The script attempts to copy a specified payload file (e.g., `sliver_payload.exe`) from the attacker's machine to the `C:\Windows\Temp\` directory on the target machine. This is done by trying to access the `admin$` administrative share (`\\<target_IP>\admin$\Temp\sliver_payload.exe`).
    *   **Note**: This requires the account running the script to have administrative privileges on the target machine, or for the target machine to have easily guessable/default credentials, or a vulnerability that grants such access (which is outside the scope of this script's direct functionality but is a prerequisite in a lab scenario).
2.  **Remote Execution**: After successfully copying the payload, the script uses Windows Management Instrumentation (WMI) via `Invoke-CimMethod -ClassName Win32_Process -MethodName Create` to remotely execute the payload on the target machine.

### Propagation Rules
-   **Infection List**: The script maintains a text file (`infected.txt` by default, in the same directory as `SRE.ps1`) that logs the IP addresses of machines it has successfully "infected." This prevents the script from repeatedly targeting the same machine.
-   **Delay**: An optional delay (`$infectionDelaySeconds`) can be configured to pause the script between infection attempts. This can make the simulation less noisy and more realistic in some scenarios.

### Persistence
- The script attempts to establish persistence on "infected" machines by creating a Scheduled Task.
- This task is configured to run the copied payload (`C:\Windows\Temp\sliver_payload.exe`) when any user logs on.
- The task is named `SystemCriticalUpdate` to appear less suspicious and runs with `NT AUTHORITY\SYSTEM` privileges.

## 3. Script Structure

### Configuration Variables
These variables are located at the beginning of `SRE.ps1` and should be configured before running the script:

-   `$payloadPath`: (String) The local path to your payload executable (e.g., `".\sliver_payload.exe"` or `"C:\Users\Attacker\Desktop\sliver_payload.exe"`). This file will be copied to victims.
-   `$sliver_URL`: (String) Example URL for downloading a Sliver C2 payload. *Currently not used for direct download in the script but provided for context or future extension.*
-   `$mimikatz_URL`: (String) Example URL for downloading Mimikatz. *Currently not used directly but provided for context or future extension.*
-   `$baseIp`: (String) The base part of the IP range to scan (e.g., `"192.168.56."`).
-   `$startIp`: (Integer) The starting number of the IP range (e.g., `1`).
-   `$endIp`: (Integer) The ending number of the IP range (e.g., `254`).
-   `$remotePayloadPath`: (String) The full path where the payload will be stored on the victim machine (e.g., `"C:\Windows\Temp\sliver_payload.exe"`).
-   `$infectedListFile`: (String) Path to the file that stores IPs of infected machines (e.g., `".\infected.txt"`).
-   `$infectionDelaySeconds`: (Integer) Number of seconds to wait between infection attempts (e.g., `10`). Set to `0` for no delay.

### Key Functions
-   `Write-Log`: Handles console logging with timestamps and severity levels.
-   `Test-SmbConnection`: Checks if port 445 is open on a target IP.
-   `Copy-Payload`: Copies the payload file to the admin$ share on the target.
-   `Execute-PayloadWmi`: Executes the payload on the target using WMI.
-   `Establish-Persistence`: Creates a scheduled task on the target to run the payload at logon.

## 4. Lab Setup and Usage

### Prerequisites
1.  **Isolated Virtual Network**:
    *   Set up a virtual network (e.g., using VirtualBox's "Host-only Network" or "Internal Network" feature).
    *   Ensure no connectivity to your actual home/corporate network or the internet unless strictly controlled for specific payload download tests (if you modify the script for that).
2.  **Attacker Machine**:
    *   A Windows VM where you will run `SRE.ps1`.
    *   PowerShell installed (usually available by default on Windows).
    *   The payload file (e.g., `sliver_payload.exe` from a C2 framework like Sliver) must be present on this machine at the path specified in `$payloadPath`.
3.  **Victim Machines**:
    *   One or more Windows VMs within the same isolated virtual network.
    *   These machines should be configured to be "vulnerable" for the educational exercise:
        *   **Firewall**: Windows Firewall might need to be configured to allow inbound SMB (port 445) and WMI traffic. For a lab, you might temporarily disable it on victim VMs *only for the duration of the experiment*.
        *   **Administrative Shares**: `admin$` share should be enabled (usually default).
        *   **Credentials**: The account used to run `SRE.ps1` on the attacker machine must have administrative privileges on the victim machines. In a lab, you can ensure all VMs use the same local administrator account and password.
        *   **Network Discovery & File Sharing**: Ensure these are enabled on victim machines.
4.  **Payload**:
    *   Have a payload ready (e.g., a beacon from Sliver C2, or even a simple `calc.exe` renamed for testing).
    *   Place it at the location you define in `$payloadPath`.

### Configuration Steps
1.  **Download/Copy `SRE.ps1`**: Place the `SRE.ps1` script on your designated attacker VM.
2.  **Prepare Payload**:
    *   Obtain or create your `sliver_payload.exe` (or other chosen payload).
    *   Place it on the attacker VM.
3.  **Edit `SRE.ps1` Configuration**:
    *   Open `SRE.ps1` in a text editor (like PowerShell ISE or VS Code).
    *   Modify the configuration variables at the top of the script:
        *   Set `$payloadPath` to the correct local path of your payload file.
        *   Adjust `$baseIp`, `$startIp`, `$endIp` if your lab network is different from `192.168.56.0/24`.
        *   Review other settings like `$infectionDelaySeconds`.
    *   Save the changes.

### Running the Script
1.  **Open PowerShell**: On the attacker VM, open a PowerShell console **as an Administrator**. This is often necessary for network operations and WMI calls, especially if dealing with User Account Control (UAC).
2.  **Navigate to Script Directory**:
    ```powershell
    cd C:\Path\To\Your\Scripts
    ```
3.  **Execution Policy**: If you haven't run PowerShell scripts before, you might need to set the execution policy. For a lab, you can use:
    ```powershell
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
    # Or for more persistent change (requires admin):
    # Set-ExecutionPolicy -ExecutionPolicy RemoteSigned
    ```
4.  **Run the Script**:
    ```powershell
    .\SRE.ps1
    ```
5.  **Monitor**:
    *   The script will output logs to the console, showing its progress: scanning IPs, attempting connections, copying files, and executing payloads.
    *   Check for the creation of `infected.txt` in the same directory.
    *   On victim machines (if the infection is successful):
        *   Look for your payload in `C:\Windows\Temp\`.
        *   Check Task Scheduler for a task named `SystemCriticalUpdate`.
        *   If your payload has a visible effect (like launching `calc.exe`) or connects back to a C2 server, observe that behavior.

## 5. Limitations
-   **Credential Dependency**: Relies on the attacker having administrative access to target machines (either through known credentials or by running in a context that already has domain admin rights in a lab domain). It does not exploit vulnerabilities to gain initial access or escalate privileges.
-   **Basic SMB/WMI Focus**: Primarily uses SMB for file copy and WMI for execution. More advanced worms use various protocols and exploit vulnerabilities.
-   **Error Handling**: Basic error handling is implemented. Robust error handling for all scenarios is complex.
-   **Evasion**: No significant AV evasion or stealth techniques are implemented. It's likely to be detected by security software in a non-lab environment.
-   **Environment Specificity**: Designed for Windows environments and specific network configurations (SMB, WMI enabled).
-   **No Self-Payloading**: The script itself doesn't carry the payload embedded within it; `$payloadPath` must point to an external file.

## 6. Disclaimer
**This script is provided "as is" without warranty of any kind. You are solely responsible for your actions and any consequences that may arise from using this script. Always ensure you have explicit permission to conduct any testing, even in a lab environment. Adhere to ethical guidelines and legal frameworks.**

---
Remember to revert any permissive changes made to victim VMs (like disabling firewalls) after your educational exercise is complete.
