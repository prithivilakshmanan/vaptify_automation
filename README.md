# 🔐 VAPTIFY – Automated VA Scanning Tool

VAPTIFY is a Vulnerability Assessment (VA) automation tool designed for security testers to minimize manual work and streamline vulnerability scanning. It is a Python-based automation tool that performs essential VA checks with intuitive CLI output.

It performs **essential security checks**, displays **live results with clear visibility**, and produces a **final vulnerability summary** — without saving any scan data locally. If you find any false positives or have ideas to improve the tool, please push a commit. We will review it and proceed accordingly.

---

## ✨ Key Features

- ✅ Real-time scanning with clear, user-friendly CLI output  
- ✅ Bold and easy-to-read section headings  
- ✅ Results displayed immediately after each check  
- ✅ Uses **VULNERABLE / NOT VULNERABLE** (audit-friendly)
- ✅ Deep **TLS / SSL analysis** using `testssl.sh`
- ✅ Supports **single domain & multiple domain scanning**
- ❌ o logs, reports, or screenshots stored (designed for privacy)

---
## 🔍 Security Checks Performed

The project runs the following security checks:
1. **SPF Record Check **
2. **DMARC Record Verification**
3. **DKIM Record Validation**
4. **Direct IP Accessibility**
5. **Missing Security Headers**
6. **Server Version Disclosure**
7. **TLS / SSL Configuration**
8. **Presence of HTTPOnly & Secure Cookie Flags**

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

## 🤝 Contributing

Contributions are welcome!  
Feel free to fork the repository, make improvements, and submit a pull request.  
Please ensure all changes follow clean coding practices and ethical security standards.

## 🤝 Evidence

<img width="1173" height="397" alt="image" src="https://github.com/user-attachments/assets/28bf64f7-4a7f-4cc6-8d32-afa9489e507e" />
<img width="827" height="241" alt="image" src="https://github.com/user-attachments/assets/a633e15a-f6fb-40da-b7ec-2fb4eeda4b50" />

