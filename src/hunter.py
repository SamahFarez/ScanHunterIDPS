import subprocess
from scapy.all import sniff, IP, TCP
from datetime import datetime, timedelta
import logging
import time
from hunter_logging import setup_logging  # Import logging setup

# Set up logging
setup_logging()

# Parameters for detection
THRESHOLD_PORT_SCAN = 1  # Lowered for aggressive detection
TIME_WINDOW = timedelta(seconds=5)  # Time window for detecting scans
BLOCK_TIMEOUT = timedelta(minutes=5)

# Track connections and last alert time
connection_attempts = {}
blocked_ips = {}

# Callback to send log messages to GUI
log_callback = None

def set_log_callback(callback):
    global log_callback
    log_callback = callback

# Function to log messages and notify GUI
def log_message(message):
    logging.info(message)  # Log to file
    if log_callback:
        log_callback(message)  # Log message to GUI

# Function to block an IP
def block_ip(ip_address):
    try:
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
        message = f"[ACTION] Blocked IP: {ip_address}"
        log_message(message)  # Log message to GUI
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
            connection_attempts[src_ip]["ports"].add(dst_port)

            if (len(connection_attempts[src_ip]["ports"]) >= THRESHOLD_PORT_SCAN and
                    (current_time - connection_attempts[src_ip]["timestamp"]) <= TIME_WINDOW):
                alert_message = f"[ALERT] Port scan detected from IP: {src_ip}"
                log_message(alert_message)  # Log alert to GUI

                if src_ip not in blocked_ips:
                    block_ip(src_ip)

                # Reset tracking after alert
                connection_attempts[src_ip]["timestamp"] = current_time
                connection_attempts[src_ip]["ports"] = set()  # Clear the ports after blocking

# Packet handler function
def packet_handler(packet):
    detect_port_scan(packet)

# Function to start sniffing
def start_sniffing():
    sniff(prn=packet_handler, store=0)
