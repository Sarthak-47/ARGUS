use std::io::{BufRead, BufReader, Read};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use tauri::{Emitter, Window};

const EVENT_SENTINEL: &str = "@@ARGUS_EVENT@@";

/// How to invoke the Argus CLI: either the `argus` console script, or a Python
/// interpreter with `-m argus`.
#[derive(Clone)]
struct ArgusCli {
  program: String,
  base_args: Vec<String>,
}

/// Probe a series of ways to reach the Argus CLI and cache the first that
/// answers `--version`. A GUI launched from the Dock/Start menu does NOT inherit
/// the shell PATH, so a `pip install`'d `argus` is frequently invisible to the
/// packaged app even though it works fine in a terminal — the single most common
/// "it says argus isn't installed but it is" complaint. We fall back to
/// `python -m argus` (works whenever Python is reachable) and a couple of the
/// usual user-install bin locations.
fn detect_argus() -> Option<ArgusCli> {
  let mut candidates: Vec<ArgusCli> = vec![ArgusCli { program: "argus".into(), base_args: vec![] }];
  for py in ["python3", "python", "py"] {
    candidates.push(ArgusCli { program: py.into(), base_args: vec!["-m".into(), "argus".into()] });
  }
  // Common user-site script locations that a Finder/Start-menu launch misses.
  if let Ok(home) = std::env::var("HOME") {
    candidates.push(ArgusCli { program: format!("{home}/.local/bin/argus"), base_args: vec![] });
  }
  if let Ok(profile) = std::env::var("USERPROFILE") {
    candidates.push(ArgusCli { program: format!("{profile}\\.local\\bin\\argus.exe"), base_args: vec![] });
  }
  candidates.into_iter().find(|c| {
    Command::new(&c.program)
      .args(&c.base_args)
      .arg("--version")
      .output()
      .map(|o| o.status.success())
      .unwrap_or(false)
  })
}

fn argus_cli() -> Result<&'static ArgusCli, String> {
  static CACHE: OnceLock<Option<ArgusCli>> = OnceLock::new();
  CACHE.get_or_init(detect_argus).as_ref().ok_or_else(|| {
    "Could not find the Argus CLI. Install it with `pip install argus-panoptes` \
     and make sure Python is on your PATH."
      .to_string()
  })
}

/// A fresh `Command` for the resolved Argus CLI, with any `-m argus` base args
/// already applied — append the subcommand and flags as usual.
fn argus_command() -> Result<Command, String> {
  let cli = argus_cli()?;
  let mut cmd = Command::new(&cli.program);
  cmd.args(&cli.base_args);
  Ok(cmd)
}

/// Runs the real Argus engine against `target` and returns the resulting
/// `report.json` contents. `mode` is "scan" (phase 1 only) or "audit" (phase
/// 1 + phase 2). Assumes `argus` is on PATH (as installed by `pip install
/// argus-panoptes`) — this is the desktop shell driving the existing CLI, not
/// a reimplementation of it.
///
/// For an `audit`, the child is run with `ARGUS_EVENT_STREAM=1` and its stdout
/// is read line by line: sentinel-prefixed lines carry a per-agent event we
/// forward to the frontend as `argus://event` so Live Attack can show a real
/// feed. Everything else (the Rich-decorated output) is ignored. If any of the
/// streaming fails, the audit still completes and the report is returned — the
/// feed is a live nicety, never load-bearing.
#[tauri::command]
fn run_audit(window: Window, target: String, mode: String, agents: Option<String>) -> Result<String, String> {
  let out_dir = std::env::temp_dir().join("argus-gui-report");
  std::fs::create_dir_all(&out_dir).map_err(|e| format!("failed to create output dir: {e}"))?;
  let out_dir_str = out_dir.to_string_lossy().to_string();

  // `scan`/`audit` write findings to Argus's own state dir; `report --output`
  // then re-exports the most recent result to a predictable path we control.
  if mode == "scan" {
    let output = argus_command()?
      .args(["scan", &target])
      .output()
      .map_err(|e| format!("failed to launch argus: {e}"))?;
    if !output.status.success() {
      return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }
  } else {
    let mut cmd = argus_command()?;
    cmd.args(["audit", &target]);
    if let Some(a) = agents.filter(|a| !a.is_empty()) {
      cmd.args(["--agents", &a]);
    }
    cmd.env("ARGUS_EVENT_STREAM", "1");
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| format!("failed to launch argus: {e}"))?;

    if let Some(stdout) = child.stdout.take() {
      for line in BufReader::new(stdout).lines().map_while(Result::ok) {
        if let Some(rest) = line.strip_prefix(EVENT_SENTINEL) {
          let _ = window.emit("argus://event", rest.to_string());
        }
      }
    }

    let status = child.wait().map_err(|e| format!("argus did not finish cleanly: {e}"))?;
    if !status.success() {
      let mut err = String::new();
      if let Some(mut stderr) = child.stderr.take() {
        let _ = stderr.read_to_string(&mut err);
      }
      return Err(if err.trim().is_empty() { "the attack failed".into() } else { err });
    }
  }

  let report_output = argus_command()?
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
  let output = argus_command()?
    .args(["history", "--format", "json", "--limit", &limit.to_string()])
    .output()
    .map_err(|e| format!("failed to launch argus: {e}"))?;
  if !output.status.success() {
    return Err(String::from_utf8_lossy(&output.stderr).into_owned());
  }
  Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Returns the raw JSON object from `argus compare --format json` — what's
/// new/fixed since the previous scan, for the Reports screen.
#[tauri::command]
fn read_scan_comparison() -> Result<String, String> {
  let output = argus_command()?
    .args(["compare", "--format", "json"])
    .output()
    .map_err(|e| format!("failed to launch argus: {e}"))?;
  if !output.status.success() {
    return Err(String::from_utf8_lossy(&output.stderr).into_owned());
  }
  Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Returns the raw JSON object from `argus status --format json` — resolved
/// provider/model, detected GPU, and configured scan/report defaults — for
/// the Sidebar and Settings screens to show real state instead of
/// placeholders that never reflect what's actually configured.
#[tauri::command]
fn read_status() -> Result<String, String> {
  let output = argus_command()?
    .args(["status", "--format", "json"])
    .output()
    .map_err(|e| format!("failed to launch argus: {e}"))?;
  if !output.status.success() {
    return Err(String::from_utf8_lossy(&output.stderr).into_owned());
  }
  Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Persists the preferred provider via `argus config --provider <name>`.
#[tauri::command]
fn set_provider(name: String) -> Result<(), String> {
  let output = argus_command()?
    .args(["config", "--provider", &name])
    .output()
    .map_err(|e| format!("failed to launch argus: {e}"))?;
  if !output.status.success() {
    return Err(String::from_utf8_lossy(&output.stderr).into_owned());
  }
  Ok(())
}

/// Persists an API key for a cloud provider via `argus config --provider
/// <name> --key <key>`.
#[tauri::command]
fn save_provider_key(name: String, key: String) -> Result<(), String> {
  let output = argus_command()?
    .args(["config", "--provider", &name, "--key", &key])
    .output()
    .map_err(|e| format!("failed to launch argus: {e}"))?;
  if !output.status.success() {
    return Err(String::from_utf8_lossy(&output.stderr).into_owned());
  }
  Ok(())
}

/// Marks a finding ignored/reviewing/open via `argus suppress`. `search`
/// must uniquely match one finding's title in the last scan (same rule the
/// CLI enforces) — an ambiguous or missing match surfaces as an error the
/// GUI shows the user rather than silently doing nothing.
#[tauri::command]
fn suppress_finding(search: String, status: String, reason: String) -> Result<(), String> {
  let mut cmd = argus_command()?;
  cmd.args(["suppress", &search, "--status", &status]);
  if !reason.is_empty() {
    cmd.args(["--reason", &reason]);
  }
  let output = cmd.output().map_err(|e| format!("failed to launch argus: {e}"))?;
  if !output.status.success() {
    return Err(String::from_utf8_lossy(&output.stderr).into_owned());
  }
  Ok(())
}

/// Cheap presence check so the GUI can tell the user to `pip install
/// argus-panoptes` instead of failing opaquely on the first real scan.
#[tauri::command]
fn check_argus_available() -> bool {
  argus_cli().is_ok()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
  tauri::Builder::default()
    .invoke_handler(tauri::generate_handler![
      run_audit, check_argus_available, read_source_snippet, read_scan_history,
      read_scan_comparison, read_status, set_provider, save_provider_key, suppress_finding
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
