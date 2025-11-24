import os
import re
import time
import threading
from datetime import datetime
from collections import defaultdict

import psutil

# Scapy ke liye root chahiye (Linux)
try:
    from scapy.all import sniff, IP
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# ==========================
# CONFIGURATION
# ==========================

AUTH_LOG_PATH = "/var/log/auth.log"     # Ubuntu/Debian
BRUTEFORCE_THRESHOLD = 5                # N failed attempts in window
BRUTEFORCE_WINDOW_SEC = 60

DDOS_PKT_THRESHOLD = 200                # packets per 10 sec from same IP
DDOS_WINDOW_SEC = 10

HIGH_CPU_THRESHOLD = 60.0               # percent
CPU_CHECK_INTERVAL = 5                  # seconds

SUSPICIOUS_PROCESS_NAMES = [
    "netcat", "nc", "nmap", "hydra", "john", "aircrack", "msfconsole"
]


# ==========================
# IDS CORE
# ==========================

class RealIDS:
    def __init__(self, alert_callback):
        """
        alert_callback: function(type_str, message, severity)
        severity: 'LOW' | 'MEDIUM' | 'HIGH'
        """
        self.alert_callback = alert_callback

        self.bruteforce_data = defaultdict(list)   # ip -> [timestamps]
        self.ddos_data = defaultdict(list)         # ip -> [timestamps]

        self.stop_flag = threading.Event()

    # ------------- UTILS -------------
    def _now_str(self):
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def raise_alert(self, atype, msg, severity="MEDIUM"):
        self.alert_callback(atype, msg, severity)

    # ------------- BRUTEFORCE / UNAUTHORIZED ACCESS -------------
    def monitor_auth_log(self):
        """
        /var/log/auth.log ko tail karega aur failed login attempts detect karega.
        """
        if not os.path.exists(AUTH_LOG_PATH):
            self.raise_alert(
                "SYSTEM",
                f"Auth log not found at {AUTH_LOG_PATH}. Bruteforce detection disabled.",
                "LOW"
            )
            return

        try:
            with open(AUTH_LOG_PATH, "r") as f:
                # file ke end se start karte hain (sirf naya read hoga)
                f.seek(0, os.SEEK_END)

                while not self.stop_flag.is_set():
                    line = f.readline()
                    if not line:
                        time.sleep(1)
                        continue

                    # Failed password (SSH) pattern
                    # Example:
                    # "Failed password for invalid user test from 1.2.3.4 port 4242 ssh2"
                    if "Failed password" in line or "authentication failure" in line:
                        ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
                        if ip_match:
                            ip = ip_match.group(1)
                        else:
                            ip = "UNKNOWN"

                        now = time.time()
                        self.bruteforce_data[ip].append(now)

                        # purane entries clean karein
                        window_start = now - BRUTEFORCE_WINDOW_SEC
                        self.bruteforce_data[ip] = [
                            t for t in self.bruteforce_data[ip] if t >= window_start
                        ]

                        if len(self.bruteforce_data[ip]) >= BRUTEFORCE_THRESHOLD:
                            msg = (f"Possible BRUTEFORCE from {ip} "
                                   f"({len(self.bruteforce_data[ip])} failed attempts in "
                                   f"{BRUTEFORCE_WINDOW_SEC} sec)")
                            self.raise_alert("BRUTEFORCE", msg, "HIGH")
        except PermissionError:
            self.raise_alert(
                "SYSTEM",
                f"No permission to read {AUTH_LOG_PATH}. Run as root for bruteforce detection.",
                "LOW"
            )

    # ------------- NETWORK / DDoS -------------
    def _packet_handler(self, pkt):
        if IP not in pkt:
            return
        src_ip = pkt[IP].src
        now = time.time()
        self.ddos_data[src_ip].append(now)

    def ddos_analyzer(self):
        """
        DDoS detection: per IP packet rate monitor karega.
        """
        while not self.stop_flag.is_set():
            now = time.time()
            window_start = now - DDOS_WINDOW_SEC

            for ip, times in list(self.ddos_data.items()):
                # window prune
                self.ddos_data[ip] = [t for t in times if t >= window_start]
                count = len(self.ddos_data[ip])

                if count >= DDOS_PKT_THRESHOLD:
                    msg = (f"High traffic from {ip}: {count} packets in "
                           f"{DDOS_WINDOW_SEC} sec (Possible DDoS)")
                    self.raise_alert("DDOS", msg, "HIGH")

            time.sleep(2)

    def network_sniffer(self):
        if not SCAPY_AVAILABLE:
            self.raise_alert(
                "SYSTEM",
                "Scapy not available. DDoS detection disabled.",
                "LOW"
            )
            return
        try:
            sniff(prn=self._packet_handler, store=False)
        except PermissionError:
            self.raise_alert(
                "SYSTEM",
                "No permission to sniff packets. Run as root for DDoS detection.",
                "LOW"
            )

    # ------------- PROCESS / SUSPICIOUS ACTIVITY -------------
    def monitor_processes(self):
        """
        High CPU aur suspicious process names detect karega.
        """
        while not self.stop_flag.is_set():
            for proc in psutil.process_iter(["pid", "name", "cpu_percent"]):
                try:
                    name = (proc.info["name"] or "").lower()
                    cpu = proc.info["cpu_percent"]  # psutil pehli baar 0 de sakta hai
                    pid = proc.info["pid"]

                    # High CPU usage (possible malware / miner / keylogger-like)
                    if cpu is not None and cpu > HIGH_CPU_THRESHOLD:
                        msg = (f"Process {name} (PID {pid}) using high CPU: {cpu:.1f}%")
                        self.raise_alert("PROCESS", msg, "MEDIUM")

                    # Suspicious tool names
                    for bad in SUSPICIOUS_PROCESS_NAMES:
                        if bad in name:
                            msg = f"Suspicious process detected: {name} (PID {pid})"
                            self.raise_alert("PROCESS", msg, "MEDIUM")
                            break

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            time.sleep(CPU_CHECK_INTERVAL)

    # ------------- CONTROL -------------
    def start_all(self):
        # Auth log monitor
        t1 = threading.Thread(target=self.monitor_auth_log, daemon=True)
        t1.start()

        # Network sniffer
        t2 = threading.Thread(target=self.network_sniffer, daemon=True)
        t2.start()

        # DDoS analyzer
        t3 = threading.Thread(target=self.ddos_analyzer, daemon=True)
        t3.start()

        # Process monitor
        t4 = threading.Thread(target=self.monitor_processes, daemon=True)
        t4.start()

    def stop_all(self):
        self.stop_flag.set()


# ==========================
# GUI
# ==========================

class IDSApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Real-Time Intrusion Detection by Abhishek Verma")
        self.root.geometry("1000x600")
        self.root.configure(bg="#151515")

        # Title
        title = tk.Label(
            root,
            text="Real-Time Intrusion Detection Dashboard",
            font=("Segoe UI", 20, "bold"),
            fg="white",
            bg="#151515"
        )
        title.pack(pady=10)

        # Top info frame
        info_frame = tk.Frame(root, bg="#151515")
        info_frame.pack(fill="x", padx=20)

        self.status_label = tk.Label(
            info_frame,
            text="Status: Monitoring...",
            font=("Segoe UI", 12),
            fg="#00ff99",
            bg="#151515"
        )
        self.status_label.pack(side="left")

        self.log_path_label = tk.Label(
            info_frame,
            text=f"Auth Log: {AUTH_LOG_PATH}",
            font=("Segoe UI", 10),
            fg="#aaaaaa",
            bg="#151515"
        )
        self.log_path_label.pack(side="right")

        # Table for alerts
        style = ttk.Style()
        style.theme_use("default")
        style.configure(
            "mystyle.Treeview",
            font=("Segoe UI", 11),
            rowheight=26,
            background="#202020",
            fieldbackground="#202020",
            foreground="white"
        )
        style.configure(
            "mystyle.Treeview.Heading",
            font=("Segoe UI", 12, "bold"),
            background="#333333",
            foreground="white"
        )
        style.map("Treeview", background=[("selected", "#444444")])

        columns = ("time", "atype", "severity", "message")
        self.tree = ttk.Treeview(
            root,
            columns=columns,
            show="headings",
            style="mystyle.Treeview"
        )

        self.tree.heading("time", text="Time")
        self.tree.heading("atype", text="Type")
        self.tree.heading("severity", text="Severity")
        self.tree.heading("message", text="Details")

        self.tree.column("time", width=150, anchor="w")
        self.tree.column("atype", width=120, anchor="center")
        self.tree.column("severity", width=90, anchor="center")
        self.tree.column("message", width=600, anchor="w")

        self.tree.pack(fill="both", expand=True, padx=20, pady=10)

        # Buttons frame
        btn_frame = tk.Frame(root, bg="#151515")
        btn_frame.pack(pady=10)

        clear_btn = tk.Button(
            btn_frame,
            text="Clear Alerts",
            font=("Segoe UI", 11, "bold"),
            bg="#ff5555",
            fg="white",
            relief="flat",
            padx=10,
            pady=5,
            command=self.clear_alerts
        )
        clear_btn.grid(row=0, column=0, padx=10)

        export_btn = tk.Button(
            btn_frame,
            text="Export Alerts",
            font=("Segoe UI", 11, "bold"),
            bg="#3b82f6",
            fg="white",
            relief="flat",
            padx=10,
            pady=5,
            command=self.export_alerts
        )
        export_btn.grid(row=0, column=1, padx=10)

        quit_btn = tk.Button(
            btn_frame,
            text="Quit",
            font=("Segoe UI", 11, "bold"),
            bg="#6b7280",
            fg="white",
            relief="flat",
            padx=10,
            pady=5,
            command=self.on_quit
        )
        quit_btn.grid(row=0, column=2, padx=10)

        # Connect IDS core
        self.ids = RealIDS(self.add_alert)
        self.ids.start_all()

        # First system info alerts
        if not SCAPY_AVAILABLE:
            self.add_alert(
                "SYSTEM",
                "Scapy not imported. Run `pip install scapy` or disable DDoS module.",
                "LOW"
            )

    # ------------ GUI methods ------------

    def add_alert(self, atype, message, severity):
        """
        IDS yaha callback karega. Thread-safe ke liye 'after' use karte hain.
        """
        def _insert():
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.tree.insert("", "end", values=(timestamp, atype, severity, message))

        self.root.after(0, _insert)

    def clear_alerts(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

    def export_alerts(self):
        if not self.tree.get_children():
            messagebox.showinfo("Export Alerts", "No alerts to export.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt")]
        )
        if not file_path:
            return

        with open(file_path, "w") as f:
            f.write("Intrusion Detection System - Alerts Log\n")
            f.write("=" * 60 + "\n\n")
            for item in self.tree.get_children():
                time_val, atype, severity, msg = self.tree.item(item)["values"]
                f.write(f"[{time_val}] [{severity}] {atype}: {msg}\n")

        messagebox.showinfo("Export Alerts", f"Alerts exported to {file_path}")

    def on_quit(self):
        self.ids.stop_all()
        self.root.destroy()


# ==========================
# MAIN
# ==========================

def main():
    root = tk.Tk()
    app = IDSApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()


