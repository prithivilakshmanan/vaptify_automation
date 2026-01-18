#!/bin/bash

echo "======================================"
echo "   VAPTIFY - Dependency Installer"
echo "======================================"

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
  echo "[!] Please run as root or use sudo"
  exit 1
fi

echo "[+] Updating system..."
apt update -y

echo "[+] Installing required system packages..."
apt install -y \
  dnsutils \
  curl \
  git \
  openssl

# Check if testssl.sh is already installed
if command -v testssl.sh >/dev/null 2>&1; then
    echo "[+] testssl.sh already installed"
else
    echo "[+] Installing testssl.sh..."
    git clone https://github.com/drwetter/testssl.sh.git /opt/testssl.sh
    ln -s /opt/testssl.sh/testssl.sh /usr/bin/testssl.sh
    chmod +x /usr/bin/testssl.sh
fi

echo "[+] Verifying installations..."

for tool in dig curl openssl testssl.sh; do
    if command -v $tool >/dev/null 2>&1; then
        echo "[✔] $tool installed"
    else
        echo "[✘] $tool NOT installed"
    fi
done

echo "======================================"
echo "   Installation Completed Successfully"
echo "   You can now run VAPTIFY 🚀"
echo "======================================"
