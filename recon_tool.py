import nmap
import csv
from datetime import datetime

def cyber_scan(target):
    nm = nmap.PortScanner()
    print(f"\n[+] Initializing scan for: {target}")
    print(f"[+] Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # -sV: Version detection, -O: OS detection, -F: Fast scan (top 100 ports)
    # Using these flags maps directly to EHEv1 Reconnaissance techniques.
    nm.scan(hosts=target, arguments='-sV -O -F')
    
    scan_results = []
    
    for host in nm.all_hosts():
        print(f"\nHost: {host} ({nm[host].hostname()})")
        print(f"State: {nm[host].state()}")
        
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                service = nm[host][proto][port]['name']
                version = nm[host][proto][port]['product']
                state = nm[host][proto][port]['state']
                
                # Highlighting risk based on ISC2 CC Domain 4 (Network Security)
                risk = "HIGH" if service in ['ftp', 'telnet', 'http'] else "Low"
                
                scan_results.append({
                    'Host': host,
                    'Port': port,
                    'Service': service,
                    'Version': version,
                    'Status': state,
                    'Risk': risk
                })
    return scan_results

def export_results(data):
    if not data:
        print("[-] No data to export.")
        return
    filename = f"recon_{datetime.now().strftime('%Y%m%d_%H%M')}.csv"
    keys = data[0].keys()
    with open(filename, 'w', newline='') as f:
        dict_writer = csv.DictWriter(f, fieldnames=keys)
        dict_writer.writeheader()
        dict_writer.writerows(data)
    print(f"\n[!] Success: Report saved as {filename}")

if __name__ == "__main__":
    target = input("Enter target (IP or CIDR, e.g., 127.0.0.1): ")
    results = cyber_scan(target)
    export_results(results)
