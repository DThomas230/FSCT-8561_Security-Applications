import nmap
import datetime
from config import HOST, PORT

TARGET = HOST
PORTS  = str(PORT)


def run_scan(target, ports):
    """Scan target host for open ports and service versions."""
    nm = nmap.PortScanner()
    print(f"[*] Scanning {target} on port {ports} ...")
    nm.scan(hosts=target, ports=ports, arguments='-sV')

    results = []
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    results.append(f"Scan time : {timestamp}")
    results.append(f"Target    : {target}")
    results.append(f"Port(s)   : {ports}")
    results.append("-" * 50)

    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in sorted(nm[host][proto].keys()):
                info    = nm[host][proto][port]
                state   = info['state']
                service = info['name']
                version = info.get('version', '')
                line = (
                    f"Host: {host} | Port: {port}/{proto} | "
                    f"State: {state} | Service: {service} {version}".strip()
                )
                results.append(line)
                print(f"  {line}")

    return results


def save_log(results):
    """Write scan results to a timestamped log file."""
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    log_file  = f"recon_log_{timestamp}.txt"
    with open(log_file, 'w') as f:
        f.write('\n'.join(results))
    print(f"\n[+] Scan log saved to: {log_file}")
    return log_file


if __name__ == '__main__':
    results = run_scan(TARGET, PORTS)
    save_log(results)

    # Pre-flight check: confirm target port is reported as open
    if any(f"Port: {PORT}" in line and "open" in line for line in results):
        print(f"[+] Pre-flight check PASSED — port {PORT} is open.")
    else:
        print(f"[!] Pre-flight check WARNING — port {PORT} may not be open yet.")
        print("    Start day4_server.py before re-running this scan.")
