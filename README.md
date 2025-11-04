# Holmes CTF 2025

## Objective
The objective of Holmes CTF 2025 was to investigate a simulated cyber intrusion across multiple data sources, identify attacker behavior, and extract key indicators left behind by the threat actor.
I also analyzed web logs, WAF logs, PCAP network captures, and CTI platform exports to uncover:
- The attacker’s user-agent
- Web shell activity
- Exfiltrated database files
- Encoder/hex-based “calling card” strings
- C2 infrastructure
- Malware campaign information
- Persistence mechanisms
- Host scanning information from CTI platforms

The goal was to simulate the full workflow of a Security Analyst or DFIR professional: **triage → analysis → correlation → intelligence enrichment → reporting.**

## Summary of All Challenges Performed
The CTF required performing the following investigations:

**1. Log Analysis – Identifying Attacker Activity**
- Reviewed access.log, application.log, and waf.log for anomalies.
- Found the attacker’s custom User-Agent string.
	- Example: “Lilnunc/4A4D - SpecterEye”
- Identified suspicious uploaded files such as the attacker’s web shell.
	- Example: temp_4A4D.php
- Located database exfiltration filename.
	- Example: database_dump_4A4D.sql

**2. Token / String Decoding Challenge**
- Identified a recurring hex-based attacker “calling card”: 4A4D
- Converted hex → ASCII to obtain meaning (“JM”).
	- Evidence shows repeated 4A4D patterns across logs.

**3. Network Forensics (PCAP)**
- Loaded the PCAP file and followed suspicious HTTP POST streams.
- Extracted message payloads, leaked values, and potential exfil paths.
	- Multiple streams documented in the file.

**4. Malware Intelligence – OmniYard Platform**
- Logged into OmniYard and reviewed the attacker’s campaign activity.
- Counted:
	- 8 campaigns, 7 tools, 8 malware records
	- Malware SHA256 hash: F32E976701571018E652581E063180F2DAD763F337A6AB68F298361A3382280C

**5. Threat Actor Infrastructure – CogWork Security**
- Looked up the malware hash in CogWork.
- Retrieved:
	- C2 IP address & port
		- Logs show C2 evidence at: 121.36.37.224:7477
	- Persistence file path
		- Logs reference: /tmp/.system_update_4A4D

**6. External Host Scanning – CogNet Scanner**
- Queried the attacker’s IP through CogNet Scanner.
- Extracted:
	- Open ports
	- Organization/ownership
	- Service banner information

## Skills Learned
**Digital Forensics & Incident Response**
- Analyzing multi-source log files for IoCs
- Identifying suspicious user-agents and upload activity
- Detecting malicious filenames and encoded attacker markers
- Building timelines of compromise events
- Extracting flags and intelligence for reporting

**Threat Hunting & Intelligence**
- Identifying common attacker tradecraft across logs
- Enriching hashes, campaigns, and infrastructure using CTI platforms
- Correlating logs, network traffic, and CTI data into a unified picture
- Understanding attacker TTPs through real-world-like telemetry

**Network Forensics**
- Filtering HTTP traffic in Wireshark
- Following TCP streams to view payloads and potential exfiltration
- Interpreting POST requests, API messages, and encoded transmissions

**Malware, Campaign, and C2 Analysis**
- Reviewing malware metadata and campaigns
- Identifying persistence mechanisms
- Extracting C2 IP and port combinations
- Understanding attacker operational patterns

**Technical Investigation Skills**
- Using PowerShell for IOC hunting
- Hex decoding & token recognition
- Hashing and file verification
- Searching large log sets efficiently
- Using security dashboards to pivot between evidence sources

## Tools Used
**Forensic & Analysis Tools**
- PowerShell (Select-String, Get-FileHash)
- Wireshark (HTTP filters, Follow TCP Stream)
- Hex/ASCII converters (token decoding)
- Text parsing & log-searching utilities

**Cyber Threat Intelligence Platforms**
- OmniYard CTI (campaigns, malware hash, metadata)
- CogWork Security (C2 mapping, persistence details)
- CogNet Scanner (open ports, service banners, host details)

**Other Utilities**
- Browser-based dashboards
- File inspection tools (strings, hex editors)

## Steps
### 1. Log Review & Initial Triage
- Searched through provided application, access, and WAF logs.
- Identified recurring tokens, anomalous activity, suspicious user-agents, web shell references, and exfiltration filenames.
- Documented all repeating artifacts for further correlation.

### 2. Pattern & Artifact Identification
- Noted consistent attacker markers (e.g., repeated hex-string themes, filename patterns).
- Extracted user-agents, upload events, and database exfiltration references.
- Built an IOC list to drive further investigation across tools.

### 3. Network Forensics
- Loaded the PCAP into Wireshark.
- Used HTTP request filters to identify beaconing, uploads, and outbound transmissions.
- Followed suspicious TCP streams to view raw payload content and potential exfil paths.

### 4. Threat Intelligence Enrichment
- Queried the identified malware hash within OmniYard to obtain malware metadata.
- Reviewed campaign counts, associated infrastructure, and attacker methods.
- Logged into CogWork Security to correlate C2 values and persistence information.
- Used CogNet Scanner to collect host details, open ports, organizational data, and banner strings.

### 5. Consolidation of Findings
- Combined log artifacts, PCAP evidence, and CTI intelligence into a unified timeline.
- Cross-referenced indicators to confirm attacker behavior, root cause, and scope.

## Summary
This CTF project provided hands-on experience with real attack telemetry, cross-platform intelligence enrichment, and forensic investigation techniques. Completing these challenges helped reinforce practical triage, network analysis, and threat-hunting workflows that align with modern SOC and DFIR responsibilities.
