#!/bin/bash

echo "========================================"
echo "      VAPTIFY - Linux Dependency Installer"
echo "========================================"

# Must be run as root
if [ "$EUID" -ne 0 ]; then
  echo "[!] Please run this installer using sudo"
  exit 1
fi

echo "[+] Updating package list..."
apt update -y

echo "[+] Installing required system tools..."
apt install -y \
  dnsutils \
  curl \
  git \
  openssl \
  dos2unix

# Install testssl.sh
if command -v testssl.sh >/dev/null 2>&1; then
  echo "[+] testssl.sh already installed"
else
  echo "[+] Installing testssl.sh..."
  git clone https://github.com/drwetter/testssl.sh.git /opt/testssl.sh
  ln -s /opt/testssl.sh/testssl.sh /usr/bin/testssl.sh
  chmod +x /usr/bin/testssl.sh
fi

echo "[+] Verifying installed tools..."

TOOLS=("dig" "curl" "openssl" "testssl.sh")

for tool in "${TOOLS[@]}"; do
  if command -v $tool >/dev/null 2>&1; then
    echo "[✔] $tool installed"
  else
    echo "[✘] $tool NOT installed"
  fi
done

echo "========================================"
echo "  Installation completed successfully"
echo "  You can now run VAPTIFY 🚀"
echo "========================================"
