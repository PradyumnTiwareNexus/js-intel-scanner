#!/usr/bin/env bash
set -e
echo "[*] Pulling latest code..."
git pull
echo "[*] Updating Python deps..."
pip install -r requirements.txt --upgrade --break-system-packages 2>/dev/null || pip install -r requirements.txt --upgrade
echo "[*] Re-running tool detection..."
python -m backend.cli detect-tools
echo "[✓] Update complete."
