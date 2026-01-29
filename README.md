# 🛡️ Sylvester Cybersecurity Labs: Automated Recon & Defense

Welcome to my security research repository. This project documents my hands-on experience with full-spectrum cybersecurity operations, ranging from automated infrastructure exploitation to defensive monitoring.

## 📁 Repository Structure

### [🚀 Lab 1: Network Reconnaissance & Exploitation](./Lab1_Network_Recon)
* **Objective:** Automate service discovery and validate critical vulnerabilities.
* **Key Achievement:** Developed a Python scanner using `python-nmap` to identify a vsFTPd 2.3.4 backdoor and successfully gained **root access** via Metasploit.

### [🛡️ Lab 2: File Integrity Monitoring (FIM)](./Lab2_FIM_Watchdog)
* **Objective:** Implement real-time detection for unauthorized system changes.
* **Key Achievement:** Created a Python watchdog script using **SHA-256 hashing** to monitor sensitive files. Successfully detected and alerted on a simulated password file breach.

---
**Tools Used:** Python, Nmap, Metasploit, SHA-256 Hashing, Linux (Kali/Metasploitable)
