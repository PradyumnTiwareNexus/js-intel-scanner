#!/usr/bin/env bash
# Builds the backend into a standalone binary via PyInstaller, then names it
# per Tauri's externalBin convention: <name>-<rust-target-triple>[.exe]
# so `tauri::api::process::Command::new_sidecar("js-intelligence-server")`
# can find it at build/run time.
set -e

cd "$(dirname "$0")"

echo "[*] Installing build deps..."
pip install pyinstaller --break-system-packages -q 2>/dev/null || pip install pyinstaller -q

echo "[*] Running PyInstaller..."
python -m PyInstaller --onefile --noconfirm --name js-intelligence-server \
  --hidden-import uvicorn.logging \
  --hidden-import uvicorn.loops \
  --hidden-import uvicorn.loops.auto \
  --hidden-import uvicorn.protocols \
  --hidden-import uvicorn.protocols.http \
  --hidden-import uvicorn.protocols.http.auto \
  --hidden-import uvicorn.protocols.websockets \
  --hidden-import uvicorn.protocols.websockets.auto \
  --hidden-import uvicorn.lifespan \
  --hidden-import uvicorn.lifespan.on \
  --collect-all fastapi \
  --collect-all starlette \
  backend/sidecar_entry.py

# Determine this machine's Rust target triple. Falls back to a manual
# override via TARGET_TRIPLE env var if `rustc` isn't installed (e.g. CI
# cross-compiling, or building the sidecar on a machine without Rust).
if [ -n "$TARGET_TRIPLE" ]; then
  TRIPLE="$TARGET_TRIPLE"
elif command -v rustc &>/dev/null; then
  TRIPLE=$(rustc -Vv | grep host | awk '{print $2}')
else
  echo "[!] rustc not found and TARGET_TRIPLE not set."
  echo "    Set it manually, e.g.: TARGET_TRIPLE=x86_64-unknown-linux-gnu ./build_sidecar.sh"
  exit 1
fi

mkdir -p src-tauri/binaries
SRC="dist/js-intelligence-server"
DEST="src-tauri/binaries/js-intelligence-server-${TRIPLE}"
if [[ "$TRIPLE" == *"windows"* ]]; then
  SRC="dist/js-intelligence-server.exe"
  DEST="${DEST}.exe"
fi

cp "$SRC" "$DEST"
chmod +x "$DEST" 2>/dev/null || true

echo "[✓] Sidecar built: $DEST"
echo "    Size: $(du -h "$DEST" | cut -f1)"
echo "    Add \"externalBin\": [\"binaries/js-intelligence-server\"] to tauri.conf.json (already set)."
