# Lab 1: Automated Network Reconnaissance & Exploitation

## 🎯 Project Objective
The goal of this lab was to develop a custom automation tool to identify live services and validate security weaknesses. This project demonstrates a complete attack lifecycle, from initial scanning to gaining root-level access on a target system.

## 🛠️ Technical Stack
* **Language:** Python 3
* **Libraries:** `python-nmap` (Service Enumeration)
* **Target OS:** Metasploitable 2 (Linux)
* **Exploitation Framework:** Metasploit (MSF)

## 🔍 Phase 1: Automated Reconnaissance
I developed `recon_tool.py` to automate the discovery phase.
* **Service Discovery:** Identified Port 21 (FTP) running **vsFTPd 2.3.4**.
* **Vulnerability Mapping:** Cross-referenced service versions against known exploits (CVE-2011-2523).
* **Output:** Generated structured CSV reports of the target's attack surface.

## 💥 Phase 2: Vulnerability Validation
Using the reconnaissance data, I performed a controlled exploitation:
* **Exploit Used:** `exploit/unix/ftp/vsftpd_234_backdoor`.
* **Result:** Successfully triggered the malicious `:)` string in the FTP banner to open a shell on port 6200.
* **Access Level:** Achieved **UID 0 (Root)**, granting full system control.

---
*Disclaimer: This project was performed in a closed lab environment for educational purposes.*
