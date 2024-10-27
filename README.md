# Scan Hunter: Scanning Detection and Prevention System (SDPS)

## Overview
Hunter is an Intrusion Detection and Prevention System (IDPS) designed to monitor network traffic and detect potential port scanning activities. It blocks malicious IP addresses and provides a graphical user interface (GUI) for real-time monitoring and management of the system.

## Features
- **Real-time Packet Sniffing**: Monitors network traffic for potential threats.
- **Port Scan Detection**: Identifies and blocks IP addresses attempting port scans.
- **Logging**: Maintains a log of detected events and actions taken.
- **Graphical User Interface**: Provides a user-friendly interface for managing the IDPS.

## Project Structure
```
/Hunter-IDPS
│
├── src/
│   ├── hunter.py           # Core functionality for sniffing and detecting intrusions
│   ├── hunter_gui.py       # GUI for interacting with the IDPS
│   └── logging_setup.py     # Logging configuration
│
├── requirements.txt        # Required Python packages
└── README.md               # Project documentation
```

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/Hunter-IDPS.git
   cd Hunter-IDPS
   ```

2. Set up a virtual environment (optional but recommended):
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. Install the required packages:
   ```bash
   pip install -r requirements.txt
   ```

## Usage
To start the Hunter IDPS, run the following command in your terminal:
```bash
cd src
sudo python3 hunter_gui.py
```

**Note**: Running the script with `sudo` is necessary for capturing packets and modifying iptables.

## Controls
- **Start Sniffing**: Begins the packet sniffing process.
- **Stop Sniffing**: Stops the packet sniffing process.
- **Exit**: Closes the application.

## Logging
Logs are saved in `hunter_log.txt`. Each entry captures significant events such as detected port scans and IP blocking actions.

## Contributions
Contributions are welcome! Please open issues or pull requests for improvements or new features.

## License
This project is licensed under the MIT License.
