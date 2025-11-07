# 🌍 Flask Real-Time Threat Map
<img width="1648" height="768" alt="screenshot" src="https://github.com/user-attachments/assets/4b019d32-3def-4bcd-a1eb-268b3c771bc0" />


A lightweight **Flask-based cybersecurity visualization platform** that displays **live global attack data** on an interactive world map.  
It continuously collects threat intelligence from multiple **public IP feeds**, geolocates attackers in real time, and visualizes **animated attack lines** between sources and targets - complete with live statistics and a detailed event table.

---

## 🚀 Features

- 🔥 **Real-time global threat visualization**  
  Animated source → target attack lines and live map updates via **Server-Sent Events (SSE)**
- 🌐 **Multiple public data feeds**  
  EmergingThreats, Blocklist.de, FeodoTracker (abuse.ch)
- 📊 **Live Statistics Dashboard**  
  Total points, flows, real-time rates, and risk-level breakdowns
- 🧭 **Bottom Panel Table**  
  Displays latest threats with country, risk type, and feed source  
  Supports filtering by risk and configurable history length
- 💡 **No API Keys Required**  
  Uses free public IP threat feeds and ip-api.com for geolocation
- 🧑‍💻 **Developed by [Abdallah Alkhatib](https://github.com/abdallahalkhatib)**

---

## ⚙️ Quick Start

### 1️⃣ Clone the repository
```bash
git clone https://github.com/<your-username>/flask-threat-map.git
cd flask-threat-map
```

### 2️⃣ Set up environment
```bash
python -m venv .venv
source .venv/bin/activate  # (Windows: .venv\Scripts\activate)
pip install flask requests cachetools
```

### 3️⃣ Run the application
```bash
python app.py
```

Then open your browser at:
```
http://127.0.0.1:5000
```

---

## 🧩 Architecture Overview

| Component | Description |
|------------|--------------|
| **Flask Backend** | Serves live data and static UI via HTTP/SSE |
| **Threat Feeds** | Pulls data from open sources like EmergingThreats and abuse.ch |
| **GeoIP Lookup** | Uses ip-api.com to determine attacker locations |
| **Leaflet.js Frontend** | Renders an animated, interactive world map |
| **Panel & HUD** | Displays live metrics, stats, and filtered threat data |

---

## 🧠 Use Cases
- Cybersecurity labs and classrooms  
- Threat intelligence demonstrations  
- Real-time SOC dashboards  
- Awareness training visualizations  

---

## 🛠️ Configuration

You can easily adjust:
- **Feed sources**: in the `FEEDS` list  
- **Refresh intervals**: via `REFRESH_SECONDS`  
- **Map appearance** or panel layout via embedded HTML/CSS  

---

## 📄 License
This project is provided under the **MIT License**.  
Feel free to fork, modify, and integrate into your own educational or research tools.

---

### 💬 Credits
Developed with ❤️ by **Abdallah Alkhatib**  
*Security Engineer | Trainer | Researcher*
