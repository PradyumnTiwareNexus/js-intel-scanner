// JS Intelligence Platform — Tauri desktop shell.
//
// Backend startup strategy:
//   1. Production build: spawn the bundled PyInstaller sidecar
//      (`binaries/js-intelligence-server-<target-triple>`) via Tauri's
//      sidecar API. No Python install needed on the end-user machine.
//   2. Dev mode / sidecar missing: fall back to `python3 -m uvicorn
//      backend.api.server:app`, which requires this repo's
//      requirements.txt to be installed (`./install.sh`).
//
// Either way, the spawned process is killed when the window closes.

use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::Duration;
use tauri::api::process::{Command as SidecarCommand, CommandChild};
use tauri::{Manager, WindowEvent};

const BACKEND_PORT: u16 = 8787;

enum Backend {
    Sidecar(CommandChild),
    Python(Child),
}

struct BackendProcess(Mutex<Option<Backend>>);

fn python_executable() -> &'static str {
    if cfg!(target_os = "windows") {
        "python"
    } else {
        "python3"
    }
}

fn try_spawn_sidecar() -> Option<CommandChild> {
    match SidecarCommand::new_sidecar("js-intelligence-server") {
        Ok(cmd) => match cmd.args([BACKEND_PORT.to_string()]).spawn() {
            Ok((_rx, child)) => Some(child),
            Err(e) => {
                eprintln!("[js-intelligence] Sidecar failed to spawn: {e}");
                None
            }
        },
        Err(e) => {
            eprintln!("[js-intelligence] Sidecar binary not found ({e}); falling back to python3.");
            None
        }
    }
}

fn spawn_python_fallback() -> std::io::Result<Child> {
    Command::new(python_executable())
        .args([
            "-m",
            "uvicorn",
            "backend.api.server:app",
            "--host",
            "127.0.0.1",
            "--port",
            &BACKEND_PORT.to_string(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
}

fn wait_for_backend_ready(max_wait: Duration) -> bool {
    use std::net::TcpStream;
    let start = std::time::Instant::now();
    while start.elapsed() < max_wait {
        if TcpStream::connect(("127.0.0.1", BACKEND_PORT)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

fn main() {
    tauri::Builder::default()
        .manage(BackendProcess(Mutex::new(None)))
        .setup(|app| {
            let backend = if let Some(child) = try_spawn_sidecar() {
                Some(Backend::Sidecar(child))
            } else {
                match spawn_python_fallback() {
                    Ok(child) => Some(Backend::Python(child)),
                    Err(e) => {
                        eprintln!(
                            "[js-intelligence] Failed to start backend via python3 either: {e}. \
                             Run install.sh, or build the sidecar with build_sidecar.sh."
                        );
                        None
                    }
                }
            };

            let state = app.state::<BackendProcess>();
            *state.0.lock().unwrap() = backend;

            if !wait_for_backend_ready(Duration::from_secs(15)) {
                eprintln!(
                    "[js-intelligence] Backend did not respond within 15s. \
                     The UI may show connection errors until it's up."
                );
            }
            Ok(())
        })
        .on_window_event(|event| {
            if let WindowEvent::CloseRequested { .. } = event.event() {
                let app_handle = event.window().app_handle();
                let state = app_handle.state::<BackendProcess>();
                if let Some(backend) = state.0.lock().unwrap().take() {
                    match backend {
                        Backend::Sidecar(child) => {
                            let _ = child.kill();
                        }
                        Backend::Python(mut child) => {
                            let _ = child.kill();
                        }
                    }
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running js-intelligence tauri app");
}
