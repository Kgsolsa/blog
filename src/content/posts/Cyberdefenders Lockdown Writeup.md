---
title: "A writeup on solving Lockdown Challenge"
date: 2026-08-11
description: "Learn how to solve DFIR challengers on cyberfenders"
tags:
  - dfir
  - cybersecurity
  - cyberdefenders

imageAlt: "Cyber Detective"
imageOG: false
hideCoverImage: false
targetKeyword: Cyberdefenders, DFIR
hideTOC: false
draft: false
---







![Cyber Detective](/posts/attachments/AI_Detective.png)








#### Scenario

TechNova Systems’ SOC has detected suspicious outbound traffic from a public-facing IIS server in its cloud platform—activity suggestive of a web-shell drop and covert connections to an unknown host.

As the forensic examiner, you have three critical artefacts in hand: a PCAP capturing the initial traffic, a full memory image of the server, and a malware sample recovered from disk. Reconstruct the intrusion and all of the attacker’s activities so TechNova can contain the breach and strengthen its defenses.
## PCAP Analysis

### Q1: Identifying Suspicious Traffic Patterns

Objective: Locate the reconnaissance source IP on the network.

Open Wireshark and load the capture file. Navigate to Statistics → Conversations → IPv4 and sort by bytes transferred. Two IPs on the 10.0.x network (a private/local network range) immediately stand out. Filter these IPs and switch to the TCP table, again sorting by byte size.

Key Finding: IP 10.0.2.4 is communicating with 10.0.2.15 across multiple ports (445, 80) originating from the same source port 55475. This pattern—using a single source port to connect to multiple destination ports on a target—is characteristic of a port scan.

Answer: 10.0.2.4

---

### Q2: Identifying the Reconnaissance Tool

Objective: Determine which tool the attacker used for HTTP-based enumeration.

Return to the main Wireshark view and refine the filter: `ip.addr==10.0.2.4 && ip.addr==10.0.2.15 && http`. Scroll through the packets to find anomalies.

Packet 2140 contains a suspicious URI request: `nmaplowercheck1725947084`. Examine the packet details, specifically the User-Agent header.

Finding: The User-Agent clearly identifies Nmap (Network Mapper), a widely-used open-source utility for network scanning and enumeration. Beyond port scanning, Nmap can perform service fingerprinting, OS detection, and web enumeration through its scripting engine (NSE—Nmap Scripting Engine).

Answer: Nmap

---

### Q3: SMB Share Enumeration

Objective: Identify which network shares the attacker probed.

Replace the `http` filter with `smb2` to isolate SMB (Server Message Block) traffic. This protocol handles file sharing and remote administration over port 445.

Finding: The attacker makes reconnaissance probes to the following UNC paths (Universal Naming Convention—the Windows format for network resource paths):

- \10.0.2.15\Documents
- \10.0.2.15\IPC$ (Inter-Process Communication share, typically used for remote administration)

Answer: \10.0.2.15\Documents and \10.0.2.15\IPC$

---

### Q4: Malicious Payload Upload

Objective: Identify the remote code execution (RCE) payload.

Continuing the SMB2 analysis, examine packet 2783. This packet shows the attacker requesting the creation of a file named shell.aspx.

Context: ASPX is a Microsoft Active Server Pages extension—executable server-side code that runs within IIS (Internet Information Services). An attacker uploading this file to a web-accessible directory gains the ability to execute arbitrary commands on the compromised server.

Recommended Actions:

- Extract the file's hash value (MD5, SHA-1, or SHA-256) for threat intelligence lookup
- Perform static analysis using the `strings` utility to identify embedded code, command-and-control domains, or suspicious function calls

Answer: shell.aspx

---

### Q5: Identifying the Reverse Shell Port

Objective: Locate the callback mechanism.

Replace the SMB2 filter with `tcp` to observe all TCP traffic. You will notice a large volume of communication on an unusual port: 4443.

Context: Port 4443 is commonly used for HTTPS (secure web traffic) but in this context serves as the reverse shell callback port—the channel through which the compromised server initiates an outbound connection back to the attacker's command-and-control (C2) infrastructure.

Answer: 4443

---

## Memory Dump Analysis

### Q6: Kernel Base Address

Objective: Extract critical kernel information from the memory dump.

Volatility 3 is a Python-based framework for analyzing memory dumps from Windows, Linux, and macOS systems. It reconstructs the system state at the moment the memory was captured.

Run the following command:

bash

```
python3 vol.py -f /your/vm/lab/dir/memdump.mem windows.info
```

Output Summary:

|Field|Value|
|---|---|
|Kernel Base|0xf80079213000|
|DTB (Directory Table Base)|0x1aa000|
|Windows Version|10 (Windows Server 2016/2019)|
|System Architecture|64-bit|
|Build Number|17763|
|System Time (UTC)|2024-09-10 06:14:13|
|Processors|4 cores|

Answer: 0xf80079213000

---

### Q7: Identifying the Persistence Mechanism

Objective: Find suspicious executables in the process list.

Run:

bash

```
python3 vol.py -f /your/vm/lab/dir/memdump.mem windows.cmdline
```

This command lists all running processes with their command-line arguments. Reviewing the output, most processes are legitimate Windows services (`svchost.exe`, `csrss.exe`, `lsass.exe`, etc.).

However, one entry stands out:

```
4200 | RegSvcs.exe | "C:\Users\admin\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\update.exe"
```

And separately:

```
900 | updatenow.exe | "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\updatenow.exe"
```

Significance: Executables placed in Startup folders (`\Start Menu\Programs\Startup\`) are launched automatically when a user logs in, providing persistence (malware survives system reboots). The naming (`update.exe`, `updatenow.exe`) mimics legitimate Windows update utilities—a common living-off-the-land evasion tactic.

Answer: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\updatenow.exe

---

### Q8: Reverse Shell Process Identification

Objective: Link the reverse shell traffic to a specific process.

The windows.netscan plugin reconstructs network connections from memory, mapping IP addresses, ports, and process IDs.

Run:

bash

```
python3 vol.py -f /home/parrot/kobold/memdump.mem windows.netscan | grep 4443
```

Output:

```
0xce0657209270.0 TCPv4 | 10.0.2.15:DB scan 49688 fin | 10.0.2.4
```

This shows outbound traffic to port 4443. Cross-referencing with the process list identifies`

- Process Name: w3wp.exe (IIS worker process)
- PID: 4332

Context: IIS applications run under `w3wp.exe`. The attacker's shell code, embedded within the uploaded ASPX file, executes under this process context—a direct consequence of uploading the malicious payload to the web server.

Answer: w3wp.exe, 4332

---

## Malware Sample Analysis

### Q9: Obtaining and Hashing the Sample

Objective: Generate a cryptographic fingerprint for threat intelligence.

Extract the suspected malware and compute its SHA-256 hash:

bash

```
sha256sum updatenow.exe
```

Output:

```
c25a6673a24d169de1bb399d226c12cdc666e0fa534149fc9fa7896ee61d406f  updatenow.exe
```

This hash uniquely identifies the binary and enables lookups on threat intelligence platforms.

---

### Q10: Packer Identification

Objective: Detect code obfuscation techniques.

Search the hash on VirusTotal: [https://www.virustotal.com/gui/file/c25a6673a24d169de1bb399d226c12cdc666e0fa534149fc9fa7896ee61d406f/details](https://www.virustotal.com/gui/file/c25a6673a24d169de1bb399d226c12cdc666e0fa534149fc9fa7896ee61d406f/details)

Finding: The binary is packed—compressed and encrypted to evade antivirus detection and hinder reverse engineering.

Packer Used: UPT

Why This Matters: Packers wrap malicious code in a protective layer. When executed, the packer unpacks (decompresses and decrypts) the payload in memory before execution. This technique makes static analysis harder but leaves traces in memory dumps—exactly what we observed in the Volatility analysis. An explainer  on malware packing techniques, refer to: [https://any.run/cybersecurity-blog/malware-packers-explained/](https://any.run/cybersecurity-blog/malware-packers-explained/)

Answer: UPT

---

### Q11: Command-and-Control Domain

Objective: Identify the attacker's infrastructure.

On VirusTotal, review the Community comments section. Users often link to detailed analysis reports. One contributor references Any.run, a sandbox platform.

Following that link reveals:

- Communication Protocol: SMTP (Simple Mail Transfer Protocol, port 25/587)
- Hard-coded Credentials: Present in the binary
- C2 Domain: cp8nl[.]hyperhost[.]ua

Context: Sending exfiltrated data via SMTP is an evasion technique—defenders often overlook email traffic, or the attacker leverages compromised mail servers for legitimate-looking outbound connections.

Answer: cp8nl[.]hyperhost[.]ua

---

### Q12: Malware Family Classification

Objective: Link the sample to a known malware lineage.

The VirusTotal report and Any.run analysis tag this sample under the AgentTesla malware family.

AgentTesla Overview:

- Type: Infostealer/Remote Access Trojan (RAT)
- Capabilities: Keylogging, credential theft, screen capture, reverse shell access
- First Seen: ~2014
- Distribution: Email phishing, malicious documents, compromised software repositories

This classification confirms the attack flow: reconnaissance → initial access (upload shell.aspx) → persistence (Startup folder) → C2 communication (SMTP to cp8nl.hyperhost.ua).

Answer: AgentTesla

---

## MITRE ATT&CK Techniques Observed

| Tactic               | Technique                                | Evidence                                     |
| -------------------- | ---------------------------------------- | -------------------------------------------- |
| Reconnaissance       | Network Service Discovery (T1046)        | Nmap port scans on IIS host                  |
| Execution            | User Execution (T1204)                   | ASPX web shell execution via IIS             |
| Persistence          | Boot or Logon Startup Folder (T1547.001) | `updatenow.exe` in Startup directory         |
| Privilege Escalation | DLL Side-Loading (T1574.002)             | Leveraging legitimate processes              |
| Discovery            | Network Share Discovery (T1135)          | SMB enumeration of Documents and IPC$ shares |
| Lateral Movement     | Remote Services (T1570)                  | SMB file upload to web-accessible share      |
| Command and Control  | Non-Standard Port (T1571)                | Reverse shell on port 4443 via w3wp.exe      |
| Exfiltration         | Exfiltration Over C2 Channel (T1041)     | Data sent to cp8nl.hyperhost.ua via SMTP     |
