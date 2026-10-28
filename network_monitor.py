import socket
import subprocess
import threading
import time
import ipaddress
import tkinter as tk
from tkinter import ttk
import re
from datetime import datetime
import json
import os
from concurrent.futures import ThreadPoolExecutor

class NetworkMonitor:
    def __init__(self):
        self.devices = {}
        self.history_file = "device_history.json"
        self.load_history()

    def get_local_network(self):
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
        return network, local_ip

    def ping(self, ip):
        try:
            result = subprocess.run(
                ['ping', '-n', '1', '-w', '500', ip],
                capture_output=True, text=True, timeout=2,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            if "TTL=" in result.stdout or "ttl=" in result.stdout.lower():
                time_match = re.search(r'time[=<](\d+)ms', result.stdout, re.IGNORECASE)
                rtt = time_match.group(1) if time_match else "N/A"
                return True, rtt
            return False, None
        except Exception:
            return False, None

    def get_arp_table(self):
        try:
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True,
                                     creationflags=subprocess.CREATE_NO_WINDOW)
            arp_dict = {}
            for line in result.stdout.split('\n'):
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([\w-]+)\s+(\w+)', line)
                if match:
                    ip, mac, _ = match.groups()
                    arp_dict[ip] = mac
            return arp_dict
        except Exception:
            return {}

    def get_hostname(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return "Unknown"

    def determine_offline_reason(self, in_arp):
        if in_arp:
            return "ICMP ব্লকড (ফায়ারওয়াল চালু) অথবা ডিভাইস স্লো রেসপন্স"
        else:
            return "ডিভাইস বন্ধ / ক্যাবল খোলা / Wi-Fi অফ / রেঞ্জের বাইরে"

    def scan_network(self, progress_callback=None):
        network, local_ip = self.get_local_network()
        arp_table = self.get_arp_table()
        results = {}
        hosts = list(network.hosts())
        total = len(hosts)
        lock = threading.Lock()

        def scan_ip(ip_obj, index):
            ip = str(ip_obj)
            is_online, rtt = self.ping(ip)
            in_arp = ip in arp_table
            mac = arp_table.get(ip, "N/A")

            with lock:
                if is_online or in_arp:
                    hostname = self.get_hostname(ip) if is_online else "Unknown"
                    status = "Online" if is_online else "Offline"
                    reason = "" if is_online else self.determine_offline_reason(in_arp)
                    results[ip] = {
                        'ip': ip, 'mac': mac, 'hostname': hostname,
                        'status': status, 'rtt': rtt if rtt else "N/A",
                        'reason': reason,
                        'last_seen': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        if is_online else self.devices.get(ip, {}).get('last_seen', 'কখনো দেখা যায়নি')
                    }
                if progress_callback:
                    progress_callback(index + 1, total)

        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(scan_ip, ip, idx) for idx, ip in enumerate(hosts)]
            for f in futures:
                f.result()

        for ip, dev in self.devices.items():
            if ip not in results and dev.get('mac', 'N/A') != 'N/A':
                dev['status'] = 'Offline'
                dev['reason'] = 'ডিভাইস সম্পূর্ণ বিচ্ছিন্ন (ARP টেবিলেও নেই)'
                results[ip] = dev

        self.devices = results
        self.save_history()
        return results

    def save_history(self):
        try:
            with open(self.history_file, 'w', encoding='utf-8') as f:
                json.dump(self.devices, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def load_history(self):
        if os.path.exists(self.history_file):
            try:
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    self.devices = json.load(f)
            except Exception:
                self.devices = {}


class App:
    def __init__(self, root):
        self.root = root
        self.root.title("নেটওয়ার্ক ডিভাইস মনিটর")
        self.root.geometry("1050x600")
        self.monitor = NetworkMonitor()
        self.scanning = False
        self.setup_ui()

    def setup_ui(self):
        top = tk.Frame(self.root)
        top.pack(fill='x', padx=10, pady=10)

        self.scan_btn = tk.Button(top, text="স্ক্যান শুরু করুন", command=self.start_scan,
                                   bg="#4CAF50", fg="white", font=('Arial', 10, 'bold'))
        self.scan_btn.pack(side='left', padx=5)

        self.auto_var = tk.BooleanVar()
        tk.Checkbutton(top, text="অটো-রিফ্রেশ (৩০ সেকেন্ড)", variable=self.auto_var,
                        command=self.toggle_auto).pack(side='left', padx=10)

        self.status_label = tk.Label(top, text="প্রস্তুত", fg="blue")
        self.status_label.pack(side='left', padx=10)

        self.summary_label = tk.Label(top, text="", font=('Arial', 10, 'bold'))
        self.summary_label.pack(side='right', padx=10)

        columns = ('IP', 'MAC', 'Hostname', 'Status', 'RTT(ms)', 'Last Seen', 'Reason')
        self.tree = ttk.Treeview(self.root, columns=columns, show='headings', height=20)
        widths = {'IP':120,'MAC':140,'Hostname':150,'Status':80,'RTT(ms)':70,'Last Seen':150,'Reason':280}
        for c in columns:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=widths.get(c,100))
        self.tree.pack(fill='both', expand=True, padx=10, pady=10)

        sb = ttk.Scrollbar(self.root, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscroll=sb.set)
        sb.pack(side='right', fill='y')

        self.tree.tag_configure('online', background='#d4edda')
        self.tree.tag_configure('offline', background='#f8d7da')

    def start_scan(self):
        if self.scanning:
            return
        self.scanning = True
        self.scan_btn.config(state='disabled', text="স্ক্যান চলছে...")
        self.status_label.config(text="স্ক্যান করা হচ্ছে...", fg="orange")
        threading.Thread(target=self.run_scan, daemon=True).start()

    def run_scan(self):
        def progress(cur, total):
            self.root.after(0, lambda: self.status_label.config(text=f"স্ক্যান: {cur}/{total}"))
        results = self.monitor.scan_network(progress_callback=progress)
        self.root.after(0, lambda: self.update_table(results))

    def update_table(self, results):
        self.tree.delete(*self.tree.get_children())
        online = offline = 0
        sorted_res = sorted(results.values(), key=lambda x: tuple(map(int, x['ip'].split('.'))))
        for d in sorted_res:
            tag = 'online' if d['status']=='Online' else 'offline'
            if d['status']=='Online': online+=1
            else: offline+=1
            self.tree.insert('', 'end', values=(
                d['ip'], d['mac'], d['hostname'], d['status'],
                d.get('rtt','N/A'), d.get('last_seen','N/A'), d.get('reason','')
            ), tags=(tag,))
        self.summary_label.config(text=f"মোট: {len(results)} | অনলাইন: {online} | অফলাইন: {offline}")
        self.status_label.config(text="সম্পন্ন ✅", fg="green")
        self.scan_btn.config(state='normal', text="স্ক্যান শুরু করুন")
        self.scanning = False

    def toggle_auto(self):
        if self.auto_var.get():
            self.auto_loop()

    def auto_loop(self):
        if self.auto_var.get():
            if not self.scanning:
                self.start_scan()
            self.root.after(30000, self.auto_loop)


if __name__ == "__main__":
    root = tk.Tk()
    App(root)
    root.mainloop()