# 🔐 VAPTIFY – Automated VA Scanning Tool

VAPTIFY is a Vulnerability Assessment (VA) automation tool designed for security testers to minimize manual work and streamline vulnerability scanning.

It performs **essential security checks**, displays **live results with clear visibility**, and produces a **final vulnerability summary** — without saving any scan data locally. If you find any false positives or have ideas to improve the tool, please push a commit. We will review it and proceed accordingly.

---

## ✨ Key Features

- ✅ Live scan with **attractive CLI output**
- ✅ Bold, easy-to-read section titles
- ✅ Results shown immediately after each check
- ✅ Uses **VULNERABLE / NOT VULNERABLE** (audit-friendly)
- ✅ Deep **TLS / SSL analysis** using `testssl.sh`
- ✅ Supports **single domain & multiple domain scanning**
- ❌ No logs, no reports, no screenshots stored (privacy-friendly)

---
## 🔍 Security Checks Performed

1. **SPF Record**
2. **DMARC Record**
3. **DKIM Record**
4. **Direct IP Accessibility**
5. **Missing Security Headers**
6. **Server Version Disclosure**
7. **TLS / SSL Configuration**
8. **Missing HTTPOnly & Secure Cookie Flags**

---

## 🖥️ Installation

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/prithivilakshmanan/vaptify_automation.git
cd vaptify_automation
chmod +x install.sh
sudo ./install.sh
python3 vaptify_va1.py -d domain.com
```

---

🚀 Usage

▶ Scan a Single Domain

```
python3 vaptify.py -d domain.com
```

▶ Scan Multiple Domains

```
python3 vaptify.py -t domains.txt
```
📌 domains.txt must contain one domain or subdomain per line.
