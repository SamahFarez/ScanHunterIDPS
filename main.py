#!/usr/bin/env python3

import subprocess
from scapy.all import sniff, IP, TCP
from datetime import datetime, timedelta
import logging
import time
import threading
import tkinter as tk
from tkinter import scrolledtext

# Set up logging
logging.basicConfig(filename="idps_log.txt", level=logging.INFO, format="%(message)s")

# Parameters for detection
THRESHOLD_PORT_SCAN = 1
TIME_WINDOW = timedelta(seconds=5)
BLOCK_TIMEOUT = timedelta(minutes=5)

# Track connections and last alert time
connection_attempts = {}
blocked_ips = {}
running = True  # Variable to control the main loop

# GUI Class
class IDPSGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Intrusion Detection and Prevention System (IDPS)")
        
        self.log_area = scrolledtext.ScrolledText(self.root, width=60, height=20)
        self.log_area.pack(pady=10)

        self.start_button = tk.Button(self.root, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = tk.Button(self.root, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        self.exit_button = tk.Button(self.root, text="Exit", command=self.exit_program)
        self.exit_button.pack(side=tk.RIGHT, padx=5)

    def log_message(self, message):
        self.log_area.insert(tk.END, message + '\n')
        self.log_area.yview(tk.END)  # Scroll to the end

    def start_sniffing(self):
        self.log_message("Starting IDPS...")
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

        # Start sniffing in a separate thread
        self.sniffer_thread = threading.Thread(target=self.sniff_packets, daemon=True)
        self.sniffer_thread.start()

    def stop_sniffing(self):
        global running
        running = False
        self.stop_button.config(state=tk.DISABLED)
        self.start_button.config(state=tk.NORMAL)
        self.log_message("Stopping IDPS...")

    def exit_program(self):
        self.stop_sniffing()  # Ensure sniffing is stopped
        self.root.quit()

    def sniff_packets(self):
        global running
        running = True
        sniff(prn=self.packet_handler, store=0)

    def packet_handler(self, packet):
        if packet.haslayer(IP) and packet.haslayer(TCP):
            src_ip = packet[IP].src
            current_time = datetime.now()

            if src_ip in blocked_ips:
                return  # Do not process packets from blocked IPs

            if src_ip not in connection_attempts:
                connection_attempts[src_ip] = {"ports": set(), "last_alert": current_time, "timestamp": current_time}

            if packet[TCP].flags == "S":
                dst_port = packet[TCP].dport
                connection_attempts[src_ip]["ports"].add(dst_port)

                if (len(connection_attempts[src_ip]["ports"]) >= THRESHOLD_PORT_SCAN and
                        (current_time - connection_attempts[src_ip]["timestamp"]) <= TIME_WINDOW):
                    alert_message = f"[ALERT] Port scan detected from IP: {src_ip}"
                    logging.info(alert_message)
                    self.log_message(alert_message)

                    if src_ip not in blocked_ips:
                        self.block_ip(src_ip)

                    connection_attempts[src_ip]["timestamp"] = current_time
                    connection_attempts[src_ip]["ports"] = set()

    def block_ip(self, ip_address):
        try:
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
            log_message = f"[ACTION] Blocked IP: {ip_address}"
            logging.info(log_message)
            self.log_message(log_message)
            blocked_ips[ip_address] = datetime.now()
        except subprocess.CalledProcessError as e:
            logging.error(f"Error blocking IP {ip_address}: {e}")

# Start the GUI
if __name__ == "__main__":
    root = tk.Tk()
    app = IDPSGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.exit_program)  # Handle window close
    root.mainloop()
