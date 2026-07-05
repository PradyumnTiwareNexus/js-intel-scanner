"""
Entry point for the PyInstaller-frozen sidecar binary.
Tauri spawns this compiled executable directly — no separate Python
install needed on the end-user machine.

Build it with build_sidecar.sh (wraps PyInstaller + correct target-triple
naming for Tauri's externalBin convention).
"""
import sys
import uvicorn

from backend.api.server import app


def main():
    port = 8787
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="info")


if __name__ == "__main__":
    main()
