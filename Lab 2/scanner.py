#!/usr/bin/env python3

import nmap
import sys
import re
import socket
import subprocess

def validate_ip_address(ip):
    # IPv4 pattern
    ipv4_pattern = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    return re.match(ipv4_pattern, ip) is not None

def validate_hostname(hostname):
    """
    Validate if the provided string is a valid hostname
    
    Args:
        hostname (str): Hostname to validate
    
    Returns:
        bool: True if valid, False otherwise
    """
    if len(hostname) > 255:
        return False
    # Hostname pattern
    hostname_pattern = r'^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$'
    return re.match(hostname_pattern, hostname) is not None

def validate_target(target):
    """
    Validate if the target is a valid IP address or hostname
    
    Args:
        target (str): Target host (IP or hostname)
    
    Returns:
        tuple: (bool, str) - (is_valid, error_message)
    """
    if not target or not target.strip():
        return False, "Target cannot be empty"
    
    target = target.strip()
    
    # Check if it's a valid IP address
    if validate_ip_address(target):
        return True, "Valid IP address"
    
    # Check if it's a valid hostname
    if validate_hostname(target):
        # Try to resolve the hostname
        try:
            socket.gethostbyname(target)
            return True, "Valid hostname (resolved)"
        except socket.gaierror:
            return False, f"Hostname '{target}' cannot be resolved to an IP address"
    
    return False, f"Invalid IP address or hostname: '{target}'"

def check_nmap_installed():
    """
    Check if Nmap is installed and accessible
    
    Returns:
        tuple: (bool, str) - (is_installed, version_or_error)
    """
    try:
        result = subprocess.run(['nmap', '--version'], 
                              capture_output=True, 
                              text=True, 
                              timeout=5)
        if result.returncode == 0:
            # Extract version from first line
            version_line = result.stdout.split('\n')[0]
            return True, version_line
        else:
            return False, "Nmap command failed"
    except FileNotFoundError:
        return False, "Nmap executable not found in system PATH"
    except subprocess.TimeoutExpired:
        return False, "Nmap version check timed out"
    except Exception as e:
        return False, f"Error checking Nmap: {str(e)}"

def scan_ports(target_host, port_range="20-1024", show_all_states=True):
    # Initialize the PortScanner object
    nm = nmap.PortScanner()
    
    print(f"\n{'='*60}")
    print(f"Starting TCP Port Scan")
    print(f"{'='*60}")
    print(f"Target Host: {target_host}")
    print(f"Port Range: {port_range}")
    print(f"{'='*60}\n")
    
    try:
        # Perform the TCP port scan
        # -sT: TCP connect scan
        # -p: specify port range
        # -Pn: treat host as online (skip host discovery)
        # --host-timeout: set timeout for the scan
        print("Scanning... This may take a moment.\n")
        print("[INFO] Setting scan timeout to 5 minutes...\n")
        nm.scan(hosts=target_host, ports=port_range, arguments='-sT -Pn --host-timeout 5m')
        
        # Print scan results
        print(f"\n{'='*60}")
        print(f"SCAN RESULTS")
        print(f"{'='*60}\n")
        
        # Check if any hosts were found
        if not nm.all_hosts():
            print("ERROR: Host is unreachable or not responding!")
            print(f"\n{'='*60}\n")
            return
        
        # Process each discovered host
        for host in nm.all_hosts():
            hostname = nm[host].hostname() if nm[host].hostname() else 'N/A'
            host_state = nm[host].state()
            
            print(f"Host: {host} ({hostname})")
            print(f"State: {host_state.upper()}")
            
            # Check if host is down or unreachable
            if host_state == 'down':
                print("\nWARNING: Host appears to be down or unreachable!")
                print(f"{'='*60}\n")
                continue
            
            print(f"\n{'Protocol':<10} {'Port':<10} {'State':<15} {'Service':<20} {'Version':<25}")
            print(f"{'-'*80}")
            
            # Track statistics
            port_stats = {'open': 0, 'closed': 0, 'filtered': 0, 'other': 0}
            open_ports_list = []
            total_ports = 0
            
            # Iterate through all scanned protocols
            for proto in nm[host].all_protocols():
                # Get all port numbers for this protocol
                ports = sorted(nm[host][proto].keys())
                total_ports += len(ports)
                
                for port in ports:
                    port_info = nm[host][proto][port]
                    state = port_info['state']
                    service = port_info.get('name', 'unknown')
                    version = port_info.get('product', '')
                    if port_info.get('version'):
                        version += f" {port_info['version']}"
                    version = version.strip() if version.strip() else 'N/A'
                    
                    # Track port statistics
                    if state in port_stats:
                        port_stats[state] += 1
                    else:
                        port_stats['other'] += 1
                    
                    # Collect open ports for summary
                    if state == 'open':
                        open_ports_list.append(port)
                    
                    # Display based on preference
                    if show_all_states or state == 'open':
                        # Color code states (using text indicators)
                        state_indicator = state.upper()
                        if state == 'open':
                            state_indicator = f"[OPEN]     "
                        elif state == 'closed':
                            state_indicator = f"[CLOSED]   "
                        elif state == 'filtered':
                            state_indicator = f"[FILTERED] "
                        
                        print(f"{proto:<10} {port:<10} {state_indicator:<15} {service:<20} {version:<25}")
            
            # Print summary
            print(f"\n{'='*60}")
            print(f"SUMMARY:")
            print(f"{'-'*60}")
            print(f"Total ports scanned: {total_ports}")
            print(f"\nPort State Breakdown:")
            print(f"  Open:     {port_stats['open']}")
            print(f"  Closed:   {port_stats['closed']}")
            print(f"  Filtered: {port_stats['filtered']}")
            if port_stats['other'] > 0:
                print(f"  Other:    {port_stats['other']}")
            
            # List all open ports
            if open_ports_list:
                print(f"\nDiscovered Open Ports: {', '.join(map(str, open_ports_list))}")
            else:
                print(f"\n[WARNING] No open ports discovered!")
            
            print(f"{'='*60}\n")
    
    except nmap.PortScannerError as e:
        error_msg = str(e).lower()
        print(f"\n{'='*60}")
        print(f"ERROR: Nmap scan failed!")
        print(f"{'='*60}")
        print(f"Details: {e}\n")
        
        # Check for specific error conditions
        if 'not found' in error_msg or 'command not found' in error_msg:
            print("[DIAGNOSIS] Nmap is not installed or not accessible!")
        elif 'permission' in error_msg or 'privilege' in error_msg:
            print("[DIAGNOSIS] Permission or privilege error detected!")
        elif 'timeout' in error_msg:
            print("[DIAGNOSIS] Network timeout occurred!")
        else:
            print("\nTroubleshooting")
        
        print(f"\n{'='*60}")
        sys.exit(1)
    
    except KeyboardInterrupt:
        print("\n\n" + "="*60)
        print("Scan interrupted by user (Ctrl+C)")
        print("="*60)
        sys.exit(0)
    
    except PermissionError as e:
        print(f"\n{'='*60}")
        print(f"ERROR: Permission denied!")
        print(f"\n{'='*60}")
        sys.exit(1)
    
    except socket.timeout:
        print(f"\n{'='*60}")
        print(f"ERROR: Network timeout!")
        print(f"{'='*60}")
        print("\n[DIAGNOSIS] Connection timed out while scanning!")
        print(f"\n{'='*60}")
        sys.exit(1)
    
    except Exception as e:
        print(f"\n{'='*60}")
        print(f"ERROR: Unexpected error occurred!")
        print(f"{'='*60}")
        print(f"Details: {e}")
        print(f"Type: {type(e).__name__}\n")
        print("Please report this error if it persists.")
        print(f"{'='*60}")
        sys.exit(1)

def main():
    """Main function to run the port scanner"""
    print("\n" + "="*60)
    print("TCP PORT SCANNER")
    print("="*60)
    
    # Step 1: Check if Nmap is installed
    print("\n[1/3] Checking Nmap installation...")
    is_installed, message = check_nmap_installed()
    if is_installed:
        print(f"[✓] Nmap found: {message}")
    else:
        print(f"\n{'='*60}")
        print(f"[✗] ERROR: Nmap not installed or inaccessible!")
        print(f"{'='*60}")
        sys.exit(1)
    
    # Define target host (localhost by default)
    target_host = "127.0.0.1"  # localhost
    
    # Step 2: Validate target host
    print(f"\n[2/3] Validating target host: {target_host}...")
    is_valid, validation_msg = validate_target(target_host)
    if is_valid:
        print(f"[✓] Target validated: {validation_msg}")
    else:
        print(f"\n{'='*60}")
        print(f"[✗] ERROR: Invalid target host!")
        print(f"{'='*60}")
        print(f"Details: {validation_msg}\n")
        print(f"{'='*60}")
        sys.exit(1)
    
    # Define port range
    port_range = "20-1024"
    
    # Step 3: Perform the scan
    print(f"\n[3/3] Starting port scan...")
    scan_ports(target_host, port_range)
    
    print("\n[✓] Scan completed successfully!")

def demonstrate_error_handling():
    print("\n" + "="*60)
    print("ERROR HANDLING DEMONSTRATION")
    print("="*60)
    
    test_cases = [
        ("127.0.0.1", "Valid localhost IP"),
        ("999.999.999.999", "Invalid IP - out of range"),
        ("192.168.1", "Invalid IP - incomplete"),
        ("invalid..hostname", "Invalid hostname format"),
        ("nonexistent-host-12345.com", "Valid format but unresolvable"),
        ("localhost", "Valid hostname"),
        ("", "Empty target"),
    ]
    
    print("\nTesting IP/Hostname Validation:\n")
    for target, description in test_cases:
        is_valid, message = validate_target(target)
        status = "[✓ VALID]" if is_valid else "[✗ INVALID]"
        print(f"{status} {description}")
        print(f"  Target: '{target}'")
        print(f"  Result: {message}\n")

if __name__ == "__main__":
    main()
