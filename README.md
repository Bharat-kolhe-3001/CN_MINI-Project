# 🛰️ WiFi Network Scanner (Python + Tkinter)

A **Computer Networks Mini Project** that scans, monitors, and analyzes nearby WiFi networks in real-time.  
Built using **Python**, **PyWiFi**, **Tkinter**, and **Matplotlib**, this tool provides a graphical interface to display detected networks, signal strength trends, and open network alerts.

---

## 📘 Project Overview

This project continuously scans for WiFi networks using the system’s wireless interface and displays:
- SSID (Network Name)
- BSSID (MAC Address)
- Signal Strength (in dBm)
- Encryption Type (OPEN/WPA/WPA2)
- Number of times detected (scan count)

It also provides **real-time statistics**, **security alerts**, and an **option to visualize signal strength variations** over time.

---

## 🧠 Key Features

✅ Real-time WiFi scanning and data logging  
✅ Multi-threaded scanning (no GUI freeze)  
✅ Signal strength graph plotting  
✅ Alerts for open (unsecured) networks  
✅ Detection of duplicate SSIDs (multiple BSSIDs)  
✅ Adjustable scan interval  
✅ Simple and interactive GUI built with Tkinter  

---

## 🖥️ Technologies Used

| Technology | Purpose |
|-------------|----------|
| **Python 3** | Programming language |
| **PyWiFi** | WiFi scanning and interface handling |
| **Tkinter** | GUI framework |
| **Matplotlib** | Plotting signal strength graphs |
| **Threading** | Background network scanning |

---

## ⚙️ Installation and Setup

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/your-username/WiFi-Network-Scanner.git
cd WiFi-Network-Scanner
