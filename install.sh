#!/bin/bash
# HNIDRS — Full Setup Script
# Run this once on a fresh machine or Pi
# Usage: sudo bash install.sh

echo "[1/4] Updating system..."
sudo apt update

echo "[2/4] Installing system dependencies..."
sudo apt install -y nmap python3-dev python3-pip python3-venv libpcap-dev

echo "[3/4] Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

echo "[4/4] Installing Python packages..."
pip install -r requirements.txt

echo ""
echo "Setup complete!"
echo "Next steps:"
echo "  1. cp .env.example .env"
echo "  2. Edit .env and set your interface (default: eth0)"
echo "  3. sudo venv/bin/python main.py --interface eth0"
