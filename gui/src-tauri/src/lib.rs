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

/// Reads up to `context` lines before and after `line` (1-indexed) from a
/// local source file, for the CodeView drill-down on static findings.
/// Returns (first_line_number, lines). Errors if the path escapes `root` —
/// a finding's `file` is a relative path from the scan report and must not
/// be trusted to read arbitrary files on disk.
#[tauri::command]
fn read_source_snippet(
  root: String,
  file: String,
  line: usize,
  context: usize,
) -> Result<(usize, Vec<String>), String> {
  let root_path = std::fs::canonicalize(&root).map_err(|e| format!("bad root: {e}"))?;
  let full_path = root_path.join(&file);
  let resolved = std::fs::canonicalize(&full_path).map_err(|e| format!("file not found: {e}"))?;
  if !resolved.starts_with(&root_path) {
    return Err("refusing to read a path outside the scanned target".into());
  }

  let contents = std::fs::read_to_string(&resolved).map_err(|e| format!("failed to read file: {e}"))?;
  let all_lines: Vec<&str> = contents.lines().collect();
  if all_lines.is_empty() {
    return Ok((1, vec![]));
  }

  let center = line.max(1) - 1; // to 0-indexed
  let start = center.saturating_sub(context);
  let end = (center + context + 1).min(all_lines.len());
  let snippet = all_lines[start..end].iter().map(|s| s.to_string()).collect();
  Ok((start + 1, snippet))
}

/// Returns the raw JSON array from `argus history --format json` for the
/// Dashboard's trend graph and "Recent Audits" list.
#[tauri::command]
fn read_scan_history(limit: usize) -> Result<String, String> {
  let output = Command::new("argus")
    .args(["history", "--format", "json", "--limit", &limit.to_string()])
    .output()
    .map_err(|e| format!("failed to launch argus: {e}"))?;
  if !output.status.success() {
    return Err(String::from_utf8_lossy(&output.stderr).into_owned());
  }
  Ok(String::from_utf8_lossy(&output.stdout).into_owned())
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
    .invoke_handler(tauri::generate_handler![
      run_audit, check_argus_available, read_source_snippet, read_scan_history
    ])
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
