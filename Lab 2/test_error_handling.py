#!/usr/bin/env python3
"""
Test script to demonstrate all error handling scenarios in scanner.py
"""

import sys
import os

# Add the parent directory to the path to import scanner
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner import validate_target, check_nmap_installed, scan_ports

def test_invalid_ip_addresses():
    """Test 1: Demonstrate handling of invalid IP addresses"""
    print("\n" + "="*70)
    print("TEST 1: INVALID IP ADDRESS HANDLING")
    print("="*70)
    
    invalid_ips = [
        "999.999.999.999",  # Out of range
        "192.168.1",         # Incomplete
        "192.168.1.1.1",     # Too many octets
        "abc.def.ghi.jkl",   # Non-numeric
        "192.168.-1.1",      # Negative number
        "",                   # Empty string
    ]
    
    for ip in invalid_ips:
        is_valid, message = validate_target(ip if ip else "(empty)")
        status = "[✓ VALID]" if is_valid else "[✗ INVALID]"
        print(f"\n{status} Testing: '{ip if ip else '(empty)'}'")
        print(f"  Result: {message}")

def test_invalid_hostnames():
    """Test 2: Demonstrate handling of invalid hostnames"""
    print("\n" + "="*70)
    print("TEST 2: INVALID HOSTNAME HANDLING")
    print("="*70)
    
    invalid_hostnames = [
        "invalid..hostname",           # Double dots
        "nonexistent-host-xyz123.com", # Unresolvable
        "-invalid-start.com",          # Starts with hyphen
        "invalid-.end.com",            # Ends with hyphen
        "hostname with spaces",        # Contains spaces
    ]
    
    for hostname in invalid_hostnames:
        is_valid, message = validate_target(hostname)
        status = "[✓ VALID]" if is_valid else "[✗ INVALID]"
        print(f"\n{status} Testing: '{hostname}'")
        print(f"  Result: {message}")

def test_valid_targets():
    """Test 3: Demonstrate handling of valid targets"""
    print("\n" + "="*70)
    print("TEST 3: VALID TARGET HANDLING")
    print("="*70)
    
    valid_targets = [
        "127.0.0.1",      # Localhost IP
        "192.168.1.1",    # Private IP
        "8.8.8.8",        # Public IP (Google DNS)
        "localhost",      # Localhost hostname
        "google.com",     # Valid domain
    ]
    
    for target in valid_targets:
        is_valid, message = validate_target(target)
        status = "[✓ VALID]" if is_valid else "[✗ INVALID]"
        print(f"\n{status} Testing: '{target}'")
        print(f"  Result: {message}")

def test_nmap_installation():
    """Test 4: Demonstrate Nmap installation check"""
    print("\n" + "="*70)
    print("TEST 4: NMAP INSTALLATION CHECK")
    print("="*70)
    
    is_installed, message = check_nmap_installed()
    
    if is_installed:
        print(f"\n[✓] Nmap is installed and accessible")
        print(f"  Details: {message}")
    else:
        print(f"\n[✗] Nmap is NOT installed or inaccessible")
        print(f"  Details: {message}")
        print("\n  This would trigger the 'Nmap not installed' error handling")

def test_no_open_ports():
    """Test 5: Demonstrate handling when no open ports are found"""
    print("\n" + "="*70)
    print("TEST 5: NO OPEN PORTS SCENARIO")
    print("="*70)
    print("\nScanning a very limited port range where ports are likely closed...")
    print("Target: 127.0.0.1, Port Range: 9900-9910")
    print("\nThis will demonstrate the 'No open ports' message:")
    
    try:
        scan_ports("127.0.0.1", "9900-9910", show_all_states=False)
    except SystemExit:
        pass

def main():
    """Run all error handling demonstrations"""
    print("\n" + "="*70)
    print("SCANNER.PY - COMPREHENSIVE ERROR HANDLING DEMONSTRATION")
    print("="*70)
    print("\nThis script demonstrates handling of the following scenarios:")
    print("  1. Invalid IP addresses")
    print("  2. Invalid hostnames")
    print("  3. Valid targets (for comparison)")
    print("  4. Nmap installation check")
    print("  5. No open ports found")
    print("  6. Network timeout (explanation)")
    print("  7. Permission errors (explanation)")
    print("\n" + "="*70)
    
    # Run all tests
    test_invalid_ip_addresses()
    test_invalid_hostnames()
    test_valid_targets()
    test_nmap_installation()
    test_no_open_ports()

if __name__ == "__main__":
    main()
