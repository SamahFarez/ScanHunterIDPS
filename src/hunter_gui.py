import sys
import os
import tkinter as tk
from tkinter import scrolledtext
import threading
from hunter import sniff, packet_handler, set_log_callback

# Add the src directory to the system path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

class HunterGUI:
    def __init__(self, master):
        self.master = master
        master.title("Hunter: Intrusion Detection and Prevention System")

        self.text_area = scrolledtext.ScrolledText(master, wrap=tk.WORD)
        self.text_area.pack(expand=True, fill='both')

        self.start_button = tk.Button(master, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(side=tk.LEFT, padx=10, pady=10)

        self.stop_button = tk.Button(master, text="Stop Sniffing", command=self.stop_sniffing)
        self.stop_button.pack(side=tk.LEFT, padx=10, pady=10)

        self.exit_button = tk.Button(master, text="Exit", command=self.exit_program)
        self.exit_button.pack(side=tk.LEFT, padx=10, pady=10)

        self.is_sniffing = False

        # Set the log callback to the GUI update function
        set_log_callback(self.log_to_gui)

    def log_to_gui(self, message):
        self.text_area.insert(tk.END, message + "\n")
        self.text_area.see(tk.END)

    def start_sniffing(self):
        self.is_sniffing = True
        self.text_area.insert(tk.END, "Starting packet sniffing...\n")
        self.text_area.see(tk.END)
        threading.Thread(target=self.sniff_packets, daemon=True).start()

    def sniff_packets(self):
        sniff(prn=packet_handler, store=0)

    def stop_sniffing(self):
        self.is_sniffing = False
        self.text_area.insert(tk.END, "Stopping packet sniffing...\n")
        self.text_area.see(tk.END)

    def exit_program(self):
        self.stop_sniffing()
        self.master.quit()

if __name__ == "__main__":
    root = tk.Tk()
    gui = HunterGUI(root)
    root.mainloop()
