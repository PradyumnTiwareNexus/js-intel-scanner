#!/usr/bin/env bash
# JS Intelligence Platform — installer for Kali/Ubuntu/Debian/WSL
set -e

echo "[*] Installing Python deps..."
pip install -r requirements.txt --break-system-packages 2>/dev/null || pip install -r requirements.txt

if ! command -v go &>/dev/null; then
  echo "[!] Go not found. Many recon tools (subfinder, httpx, katana...) need Go."
  echo "    Install from https://go.dev/doc/install then re-run this script."
else
  echo "[*] Installing Go-based recon tools (skips any already installed)..."
  GO_TOOLS=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/tomnomnom/assetfinder@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/hakluke/hakrawler@latest"
    "github.com/jaeles-project/gospider@latest"
  )
  for t in "${GO_TOOLS[@]}"; do
    echo "  -> go install $t"
    go install "$t" || echo "     [!] failed, skipping"
  done
  echo "[*] Make sure \$(go env GOPATH)/bin is in your PATH."
fi

if ! command -v amass &>/dev/null; then
  echo "[!] amass not found — install via your package manager (apt install amass) or see:"
  echo "    https://github.com/owasp-amass/amass"
fi

if ! command -v trufflehog &>/dev/null; then
  echo "[!] trufflehog not found — install via:"
  echo "    curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin"
fi

mkdir -p exports logs
echo "[*] Running tool auto-detection..."
python -m backend.cli detect-tools

echo ""
echo "[✓] Install step complete. Run: python -m backend.cli scan example.com"
