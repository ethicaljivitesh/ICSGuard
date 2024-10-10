import socket
import struct
import sys
import threading
import argparse
import logging
from scapy.all import *

# Configure logging
logging.basicConfig(filename='ics_scan.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

def log_message(message, level="info"):
    """Logs and prints a message based on the severity level."""
    if level == "info":
        logging.info(message)
    elif level == "warning":
        logging.warning(message)
    elif level == "error":
        logging.error(message)
    print(message)

# Function to scan for open ports on ICS protocols
def port_scan(target_ip, port, socket_timeout):
    """Scans the given port on the target IP."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(socket_timeout)
    result = sock.connect_ex((target_ip, port))
    sock.close()
    return result == 0

# Modbus Vulnerability Scan (Port 502)
def modbus_scan(target_ip, socket_timeout):
    """Performs a Modbus TCP vulnerability scan."""
    if port_scan(target_ip, 502, socket_timeout):
        log_message(f"[+] Modbus TCP (Port 502) Open on {target_ip}")
        try:
            # Send a Modbus read request
            request = struct.pack('>HHHBBHH', 1, 0, 6, 1, 3, 0, 1)  # Example read holding registers
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((target_ip, 502))
            sock.send(request)
            response = sock.recv(1024)
            if response:
                log_message(f"[+] Modbus response: {response}")
                # Perform basic fingerprinting
                log_message(f"[+] Modbus device may be vulnerable. Data received: {response}")
            sock.close()
        except (socket.timeout, socket.error) as e:
            log_message(f"[!] Modbus scan failed: {e}", "error")
    else:
        log_message(f"[-] Modbus TCP (Port 502) Closed on {target_ip}")

# DNP3 Vulnerability Scan (Port 20000)
def dnp3_scan(target_ip, socket_timeout):
    """Performs a DNP3 vulnerability scan."""
    if port_scan(target_ip, 20000, socket_timeout):
        log_message(f"[+] DNP3 (Port 20000) Open on {target_ip}")
        try:
            # DNP3 example request (DNP3 usually requires more complex interactions)
            request = b'\x05\x64\x0A\xC0\x01\x00\x00\x01\x02\x00\x00'
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((target_ip, 20000))
            sock.send(request)
            response = sock.recv(1024)
            if response:
                log_message(f"[+] DNP3 response: {response}")
                log_message("[+] DNP3 device may be vulnerable. Data received.")
            sock.close()
        except (socket.timeout, socket.error) as e:
            log_message(f"[!] DNP3 scan failed: {e}", "error")
    else:
        log_message(f"[-] DNP3 (Port 20000) Closed on {target_ip}")

# BACnet Vulnerability Scan (Port 47808)
def bacnet_scan(target_ip, socket_timeout):
    """Performs a BACnet vulnerability scan."""
    if port_scan(target_ip, 47808, socket_timeout):
        log_message(f"[+] BACnet (Port 47808) Open on {target_ip}")
        try:
            # BACnet Who-Is request
            request = b'\x81\x0b\x00\x0c\x01\x20\xff\xff\x00\xff\x10\x08'
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(request, (target_ip, 47808))
            sock.settimeout(socket_timeout)
            response, addr = sock.recvfrom(1024)
            if response:
                log_message(f"[+] BACnet response: {response}")
                log_message("[+] BACnet device may be vulnerable.")
            sock.close()
        except (socket.timeout, socket.error) as e:
            log_message(f"[!] BACnet scan failed: {e}", "error")
    else:
        log_message(f"[-] BACnet (Port 47808) Closed on {target_ip}")

# S7Comm Vulnerability Scan (Port 102)
def s7comm_scan(target_ip, socket_timeout):
    """Performs a Siemens S7Comm vulnerability scan."""
    if port_scan(target_ip, 102, socket_timeout):
        log_message(f"[+] Siemens S7Comm (Port 102) Open on {target_ip}")
        try:
            # Example connection request for S7Comm
            request = b'\x03\x00\x00\x16\x11\xe0\x00\x00\x00\x01\x00\xc1\x02\x01\x00\xc2\x02\x01\x02'
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((target_ip, 102))
            sock.send(request)
            response = sock.recv(1024)
            if response:
                log_message(f"[+] S7Comm response: {response}")
                log_message("[+] S7Comm device may be vulnerable.")
            sock.close()
        except (socket.timeout, socket.error) as e:
            log_message(f"[!] S7Comm scan failed: {e}", "error")
    else:
        log_message(f"[-] Siemens S7Comm (Port 102) Closed on {target_ip}")

# Main scan function for a given IP
def scan_ics(target_ip, socket_timeout):
    """Performs scans on various ICS protocols."""
    log_message(f"[*] Scanning ICS protocols on {target_ip}")
    
    # Use threads to perform scans in parallel
    threads = []
    threads.append(threading.Thread(target=modbus_scan, args=(target_ip, socket_timeout)))
    threads.append(threading.Thread(target=dnp3_scan, args=(target_ip, socket_timeout)))
    threads.append(threading.Thread(target=bacnet_scan, args=(target_ip, socket_timeout)))
    threads.append(threading.Thread(target=s7comm_scan, args=(target_ip, socket_timeout)))
    
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

if __name__ == "__main__":
    # Argument parsing
    parser = argparse.ArgumentParser(description="ICS Vulnerability Scanner")
    parser.add_argument("target_ip", help="Target IP address to scan")
    parser.add_argument("--timeout", type=int, default=3, help="Timeout for socket connections (in seconds)")
    parser.add_argument("--retries", type=int, default=1, help="Number of retries for connection")
    
    args = parser.parse_args()

    target_ip = args.target_ip
    socket_timeout = args.timeout
    retries = args.retries

    # Start scanning
    scan_ics(target_ip, socket_timeout)
