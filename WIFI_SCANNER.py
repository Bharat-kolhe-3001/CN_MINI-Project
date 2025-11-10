import pywifi
from pywifi import const
import tkinter as tk
from tkinter import ttk
from threading import Thread, Lock
import time
import matplotlib.pyplot as plt
from collections import defaultdict   



networks = {}  # bssid: {'ssid':, 'crypto':, 'signals':[], 'timestamps':[], 'counts':0}
alerts = []
lock = Lock()
    
wifi = pywifi.PyWiFi()
iface = wifi.interfaces()[0]  # first Wi-Fi interface

# Default scan interval (seconds)
scan_interval = 3

def scan_networks():
    global scan_interval
    while True:
        iface.scan()
        time.sleep(2)  # wait for scan results
        results = iface.scan_results()
        with lock:
            for net in results:
                bssid = net.bssid.upper()
                ssid = net.ssid if net.ssid else "Hidden"
                signal = net.signal
                crypto = "OPEN" if not net.akm else ', '.join([str(k) for k in net.akm])
                if bssid not in networks:
                    networks[bssid] = {'ssid': ssid, 'crypto': crypto, 'signals': [], 'timestamps': [], 'counts': 0}
                net_data = networks[bssid]
                net_data['counts'] += 1
                net_data['signals'].append(signal)
                net_data['timestamps'].append(time.time())
                
                # Alerts
                alert_open = f"Open network: {ssid} ({bssid})"
                if "OPEN" in crypto and alert_open not in alerts:
                    alerts.append(alert_open)

        check_duplicates()
        time.sleep(scan_interval)  # Use user-defined interval

def check_duplicates():
    ssid_bssids = defaultdict(list)
    with lock:
        for bssid, net in networks.items():
            ssid_bssids[net['ssid']].append(bssid)
        for ssid, bss_list in ssid_bssids.items():
            if len(bss_list) > 1:
                alert = f"Duplicate SSID: {ssid} ({len(bss_list)} BSSIDs)"
                if alert not in alerts:
                    alerts.append(alert)

def update_gui():
    while True:
        with lock:
            # Update network list
            listbox.delete(0, tk.END)
            for bssid, net in sorted(networks.items(), key=lambda x: x[1]['ssid']):
                ssid = net['ssid']
                signal = net['signals'][-1] if net['signals'] else "N/A"
                crypto = net['crypto']
                count = net['counts']
                line = f"SSID: {ssid}  BSSID: {bssid}  Signal: {signal} dBm  Encryption: {crypto}  Scans: {count}"
                listbox.insert(tk.END, line)

            # Update stats
            stats_text.delete(1.0, tk.END)
            total_networks = len(networks)
            stats_text.insert(tk.END, f"Total Networks Detected: {total_networks}\n")
            stats_text.insert(tk.END, "\nPer Network Scan Counts:\n")
            for bssid, net in networks.items():
                stats_text.insert(tk.END, f"{net['ssid']} ({bssid}): {net['counts']}\n")

            # Update alerts
            alerts_text.delete(1.0, tk.END)
            for alert in alerts:
                alerts_text.insert(tk.END, alert + "\n")

        time.sleep(1)

def show_graph():
    selected = listbox.curselection()
    if not selected:
        return
    line = listbox.get(selected[0])
    parts = line.split()
    bssid_index = parts.index("BSSID:") + 1 if "BSSID:" in parts else -1
    if bssid_index == -1:
        return
    bssid = parts[bssid_index]
    with lock:
        if bssid in networks:
            net = networks[bssid]
            if net['signals']:
                plt.figure()
                plt.plot(net['timestamps'], net['signals'])
                plt.xlabel('Time (s)')
                plt.ylabel('Signal Strength (dBm)')
                plt.title(f"Signal Strength over Time for {net['ssid']} ({bssid})")
                plt.show()

def set_scan_interval():
    global scan_interval
    try:
        val = float(scan_interval_entry.get())
        if val < 1:
            val = 1
        scan_interval = val
    except ValueError:
        scan_interval_entry.delete(0, tk.END)
        scan_interval_entry.insert(0, str(scan_interval))

# GUI setup
root = tk.Tk()
root.title("WiFi Network Scanner (Windows)")

notebook = ttk.Notebook(root)
notebook.pack(fill='both', expand=True)

# Networks tab
networks_frame = ttk.Frame(notebook)
notebook.add(networks_frame, text='Networks')
tk.Label(networks_frame, text="Scan Interval (seconds):").pack(pady=5)
scan_interval_entry = tk.Entry(networks_frame, width=5)
scan_interval_entry.insert(0, str(scan_interval))
scan_interval_entry.pack(pady=5)
scan_interval_button = tk.Button(networks_frame, text="Set Interval", command=set_scan_interval)
scan_interval_button.pack(pady=5)

listbox = tk.Listbox(networks_frame, width=100, height=20, font=("Courier", 10))
listbox.pack(pady=5)


# Statistics tab
stats_frame = ttk.Frame(notebook)
notebook.add(stats_frame, text='Statistics')
stats_text = tk.Text(stats_frame, width=100, height=25)
stats_text.pack(pady=5)

# Alerts tab
alerts_frame = ttk.Frame(notebook)
notebook.add(alerts_frame, text='Alerts')
alerts_text = tk.Text(alerts_frame, width=100, height=25)
alerts_text.pack(pady=5)

# Start scanning threads
scan_thread = Thread(target=scan_networks)
scan_thread.daemon = True
scan_thread.start()

update_thread = Thread(target=update_gui)
update_thread.daemon = True
update_thread.start()

root.mainloop()
