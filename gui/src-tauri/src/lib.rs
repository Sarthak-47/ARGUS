use std::process::Command;

/// Runs the real Argus engine against `target` and returns the resulting
/// `report.json` contents. `mode` is "scan" (phase 1 only) or "audit" (phase
/// 1 + phase 2). Assumes `argus` is on PATH (as installed by `pip install
/// argus-sec`) — this is the desktop shell driving the existing CLI, not a
/// reimplementation of it.
#[tauri::command]
fn run_audit(target: String, mode: String, agents: Option<String>) -> Result<String, String> {
  let out_dir = std::env::temp_dir().join("argus-gui-report");
  std::fs::create_dir_all(&out_dir).map_err(|e| format!("failed to create output dir: {e}"))?;
  let out_dir_str = out_dir.to_string_lossy().to_string();

  // `scan`/`audit` write findings to Argus's own state dir; `report --output`
  // then re-exports the most recent result to a predictable path we control.
  if mode == "scan" {
    let output = Command::new("argus")
      .args(["scan", &target])
      .output()
      .map_err(|e| format!("failed to launch argus: {e}"))?;
    if !output.status.success() {
      return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }
  } else {
    let mut cmd = Command::new("argus");
    cmd.args(["audit", &target]);
    if let Some(a) = agents.filter(|a| !a.is_empty()) {
      cmd.args(["--agents", &a]);
    }
    let output = cmd.output().map_err(|e| format!("failed to launch argus: {e}"))?;
    if !output.status.success() {
      return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }
  }

  let report_output = Command::new("argus")
    .args(["report", "--format", "json", "--output", &out_dir_str])
    .output()
    .map_err(|e| format!("failed to export report: {e}"))?;
  if !report_output.status.success() {
    return Err(String::from_utf8_lossy(&report_output.stderr).into_owned());
  }

  std::fs::read_to_string(out_dir.join("report.json"))
    .map_err(|e| format!("failed to read report.json: {e}"))
}

/// Cheap presence check so the GUI can tell the user to `pip install
/// argus-sec` instead of failing opaquely on the first real scan.
#[tauri::command]
fn check_argus_available() -> bool {
  Command::new("argus")
    .arg("--version")
    .output()
    .map(|o| o.status.success())
    .unwrap_or(false)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
  tauri::Builder::default()
    .invoke_handler(tauri::generate_handler![run_audit, check_argus_available])
    .setup(|app| {
      if cfg!(debug_assertions) {
        app.handle().plugin(
          tauri_plugin_log::Builder::default()
            .level(log::LevelFilter::Info)
            .build(),
        )?;
      }
      Ok(())
    })
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}
