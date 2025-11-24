# Suspicious_deterctor
# Real-Time Intrusion Detection System (IDS)
A Python-based **real-time Intrusion Detection System (IDS)** designed to detect suspicious activities such as:

- SSH Bruteforce Attacks  
- Unauthorized Login Attempts  
- DDoS Traffic Patterns  
- High CPU Usage (Possible Malicious Process)  
- Suspicious Process Names (e.g., nmap, hydra, etc.)

This IDS includes a **modern graphical dashboard (GUI)** to display alerts in real time.

---

## 📌 Features

### 🔐 1. Bruteforce / Unauthorized Access Detection
Reads the Linux `/var/log/auth.log` file in real time and detects:
- Multiple failed login attempts
- Authentication failures
- Possible bruteforce pattern within a time window

---

### 🌐 2. DDoS Detection (Packet-Based)
Uses `scapy` to sniff live network packets and detects:
- Unusual packet spikes from a single IP
- SYN flood-like behavior
- Abnormal traffic volume

---

### ⚙️ 3. Suspicious Process Monitoring
Uses `psutil` to detect:
- High CPU usage processes
- Suspicious names: `nmap`, `nc`, `hydra`, etc.
- Potential malware behavior

---

### 🖥️ 4. Real-Time GUI Dashboard
Built with **Tkinter**, featuring:
- Dark modern theme
- Attack type, severity, timestamp
- Auto-updating table
- Export alerts to a file
- Clear alerts button

---

## 📦 Requirements

Install dependencies using:

```bash
pip install -r requirements.txt

