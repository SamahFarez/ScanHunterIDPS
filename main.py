import subprocess
from scapy.all import sniff, IP, TCP
from datetime import datetime, timedelta
import logging
import time
import threading

# Set up logging
logging.basicConfig(filename="idps_log.txt", level=logging.INFO, format="%(message)s")

# Parameters for detection
THRESHOLD_PORT_SCAN = 1  # Lowered for aggressive detection
TIME_WINDOW = timedelta(seconds=5)  # Time window for detecting scans
BLOCK_TIMEOUT = timedelta(minutes=5)

# Track connections and last alert time
connection_attempts = {}
blocked_ips = {}

# Function to block an IP
def block_ip(ip_address):
    try:
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
        log_message = f"[ACTION] Blocked IP: {ip_address}"
        logging.info(log_message)
        print(log_message)  # Console output for blocking
        blocked_ips[ip_address] = datetime.now()
    except subprocess.CalledProcessError as e:
        logging.error(f"Error blocking IP {ip_address}: {e}")

# Function to detect port scans
def detect_port_scan(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        current_time = datetime.now()

        # Check if the source IP is blocked
        if src_ip in blocked_ips:
            return  # Do not process packets from blocked IPs

        # Initialize tracking for the source IP if not already done
        if src_ip not in connection_attempts:
            connection_attempts[src_ip] = {"ports": set(), "last_alert": current_time, "timestamp": current_time}

        # Check for SYN packets (part of the TCP handshake)
        if packet[TCP].flags == "S":  # SYN flag is set
            dst_port = packet[TCP].dport
            # Add the destination port to the set of ports accessed
            connection_attempts[src_ip]["ports"].add(dst_port)

            # Check if the number of distinct ports exceeds the threshold in the defined time window
            if (len(connection_attempts[src_ip]["ports"]) >= THRESHOLD_PORT_SCAN and
                    (current_time - connection_attempts[src_ip]["timestamp"]) <= TIME_WINDOW):
                alert_message = f"[ALERT] Port scan detected from IP: {src_ip}"
                logging.info(alert_message)
                print(alert_message)  # Console output for alerts

                if src_ip not in blocked_ips:
                    block_ip(src_ip)

                # Reset tracking after alert
                connection_attempts[src_ip]["timestamp"] = current_time
                connection_attempts[src_ip]["ports"] = set()  # Clear the ports after blocking

# Packet handler function
def packet_handler(packet):
    detect_port_scan(packet)

# Function to unblock an IP
def unblock_ip(ip_address):
    try:
        subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
        log_message = f"[ACTION] Unblocked IP: {ip_address}"
        logging.info(log_message)
        print(log_message)  # Console output for unblocking
        del blocked_ips[ip_address]
    except subprocess.CalledProcessError as e:
        logging.error(f"Error unblocking IP {ip_address}: {e}")

def check_for_unblocking():
    current_time = datetime.now()
    for ip, block_time in list(blocked_ips.items()):
        if current_time - block_time > BLOCK_TIMEOUT:
            unblock_ip(ip)

def unblocker_thread():
    while True:
        check_for_unblocking()
        # Log the current blocked IPs
        logging.info(f"[INFO] Current blocked IPs: {list(blocked_ips.keys())}")
        time.sleep(60)  # Check every minute

# Start the unblocker thread
threading.Thread(target=unblocker_thread, daemon=True).start()

# Start sniffing packets
print("Starting IDPS...")
sniff(prn=packet_handler, store=0)
