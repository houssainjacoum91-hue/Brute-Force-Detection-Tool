# 🛡️ Brute-Force-Detection-Tool

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Security](https://img.shields.io/badge/Focus-Blue%20Team%20%2F%20Access%20Control-red?style=flat-square)

**Advanced Python tool to detect brute-force login attempts and classify threat severity.**

---

## 🎯 Overview
**Brute-Force-Detection-Tool** is a specialized defensive security script built to monitor authentication logs and identify malicious credential-stuffing or brute-force login attempts. By tracking failure frequencies and time intervals per IP address, it automatically classifies the severity of each attack to help administrators respond swiftly.

---

## ✨ Key Features
- **Automated Attack Detection:** Scans authentication logs to spot repeated failed login patterns across services (SSH, Web, FTP).
- **Threat Severity Classification:** Categorizes suspicious IPs into Low, Medium, High, or Critical risk tiers based on attempt volume.
- **Time-Window Analysis:** Detects rapid automated bursts versus slow, distributed brute-force attacks.
- **Actionable Reporting:** Outputs clean summaries and blocks/flags offending IP addresses for firewall integration.

---

## ⚙️ Installation

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/houssainjacoum91-hue/Brute-Force-Detection-Tool.git](https://github.com/houssainjacoum91-hue/Brute-Force-Detection-Tool.git)
   cd Brute-Force-Detection-Tool
