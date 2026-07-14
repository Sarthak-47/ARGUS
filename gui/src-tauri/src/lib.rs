use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};
use tauri::{Emitter, Manager, Window};

/// The installed app's own resource directory (set once in `.setup()`), so
/// `detect_argus` can find the Argus CLI binary bundled directly inside the
/// installer — see `bundled_argus_path`.
static RESOURCE_DIR: OnceLock<PathBuf> = OnceLock::new();

const EVENT_SENTINEL: &str = "@@ARGUS_EVENT@@";

/// PID of the currently-running `argus audit` child, if any, so a separate
/// `cancel_audit` call can find and kill it — `run_audit` blocks its own
/// command thread on `child.wait()`, so cancellation has to come from another
/// command invocation running concurrently on Tauri's thread pool.
static AUDIT_CHILD: Mutex<Option<u32>> = Mutex::new(None);
/// Set by `cancel_audit` so `run_audit` can tell a killed child apart from one
/// that simply failed on its own, and report "canceled" instead of a stray
/// stderr message from being killed mid-request.
static AUDIT_CANCELED: Mutex<bool> = Mutex::new(false);

/// Windows flashes a visible console window for every spawned console-mode
/// subprocess (argus, python, py) unless CREATE_NO_WINDOW is set — invisible
/// on other platforms, but on Windows this GUI app was popping and closing a
/// cmd window for every single probe/invocation, repeatedly, which is exactly
/// what looked like the app "flickering and hanging."
#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// A `Command` that never flashes a console window on Windows — use this
/// everywhere instead of `Command::new` directly.
fn new_command(program: &str) -> Command {
  #[allow(unused_mut)]
  let mut cmd = Command::new(program);
  #[cfg(target_os = "windows")]
  {
    use std::os::windows::process::CommandExt;
    cmd.creation_flags(CREATE_NO_WINDOW);
  }
  cmd
}

/// How to invoke the Argus CLI: either the `argus` console script, or a Python
/// interpreter with `-m argus`.
#[derive(Clone)]
struct ArgusCli {
  program: String,
  base_args: Vec<String>,
}

/// The packaged app ships its own self-contained Argus CLI binary (see
/// `bundled_argus_path`), so this should be unreachable for anyone running the
/// installer as-is. It only shows up when running from source without the
/// bundle present, or if the bundled binary was somehow removed/corrupted —
/// hence pointing at both a normal install and the manual override.
const NOT_FOUND_MSG: &str = "Could not find the Argus CLI. Install it with `pip install argus-panoptes`, \
  or set its path manually in Settings (e.g. the `argus`/`argus.exe` inside a venv's \
  Scripts/bin folder).";

/// Where the user's manually-configured Argus CLI path is persisted, so it
/// survives restarts. Written as plain text (just the path) — no need for a
/// structured config format for a single value.
fn override_path_file() -> Option<std::path::PathBuf> {
  let dir = if let Ok(appdata) = std::env::var("APPDATA") {
    std::path::PathBuf::from(appdata).join("dev.argussec.desktop")
  } else if let Ok(home) = std::env::var("HOME") {
    let base = std::path::PathBuf::from(&home);
    if cfg!(target_os = "macos") {
      base.join("Library/Application Support/dev.argussec.desktop")
    } else {
      base.join(".config/dev.argussec.desktop")
    }
  } else {
    return None;
  };
  Some(dir.join("argus_path.txt"))
}

fn read_override() -> Option<String> {
  let path = override_path_file()?;
  let s = std::fs::read_to_string(path).ok()?;
  let trimmed = s.trim().to_string();
  if trimmed.is_empty() { None } else { Some(trimmed) }
}

fn write_override(path: &str) -> Result<(), String> {
  let file = override_path_file().ok_or("could not determine a config directory")?;
  if let Some(parent) = file.parent() {
    std::fs::create_dir_all(parent).map_err(|e| format!("failed to create config dir: {e}"))?;
  }
  std::fs::write(&file, path).map_err(|e| format!("failed to save path: {e}"))
}

fn probe(program: &str, base_args: &[&str]) -> bool {
  new_command(program)
    .args(base_args)
    .arg("--version")
    .output()
    .map(|o| o.status.success())
    .unwrap_or(false)
}

/// Path to the Argus CLI binary bundled directly inside this installed app
/// (see packaging/argus.spec + tauri.{windows,macos,linux}.conf.json's
/// `bundle.resources`) — a standalone, self-contained executable with no
/// dependency on a system Python or a separate `pip install argus-panoptes`.
/// This is what makes the packaged app work out of the box; PATH-based
/// detection below only matters when running from source in dev mode.
fn bundled_argus_path() -> Option<PathBuf> {
  let dir = RESOURCE_DIR.get()?;
  let name = if cfg!(target_os = "windows") { "argus-cli.exe" } else { "argus-cli" };
  let candidate = dir.join("argus-cli").join(name);
  if candidate.exists() { Some(candidate) } else { None }
}

/// Probe a series of ways to reach the Argus CLI and return the first that
/// answers `--version`: a manually-configured override first (highest
/// priority — the user told us exactly where it is), then the binary bundled
/// inside this app (the normal case for anyone who just downloaded the
/// installer), then the `argus` script, then `python -m argus` (works
/// whenever *some* Python on PATH has it installed — the dev-from-source
/// case), then a couple of the usual user-install bin locations.
fn detect_argus() -> Option<ArgusCli> {
  if let Some(path) = read_override() {
    if probe(&path, &[]) {
      return Some(ArgusCli { program: path, base_args: vec![] });
    }
  }
  if let Some(path) = bundled_argus_path() {
    let path_str = path.to_string_lossy().into_owned();
    if probe(&path_str, &[]) {
      return Some(ArgusCli { program: path_str, base_args: vec![] });
    }
  }
  let mut candidates: Vec<ArgusCli> = vec![ArgusCli { program: "argus".into(), base_args: vec![] }];
  for py in ["python3", "python", "py"] {
    candidates.push(ArgusCli { program: py.into(), base_args: vec!["-m".into(), "argus".into()] });
  }
  if let Ok(home) = std::env::var("HOME") {
    candidates.push(ArgusCli { program: format!("{home}/.local/bin/argus"), base_args: vec![] });
  }
  if let Ok(profile) = std::env::var("USERPROFILE") {
    candidates.push(ArgusCli { program: format!("{profile}\\.local\\bin\\argus.exe"), base_args: vec![] });
  }
  candidates.into_iter().find(|c| {
    let refs: Vec<&str> = c.base_args.iter().map(|s| s.as_str()).collect();
    probe(&c.program, &refs)
  })
}

/// Cache of the resolved CLI, memoizing both outcomes: `Some(None)` means "we
/// already probed this session and found nothing" — not just `None` meaning
/// "never probed." Without caching the negative case too, every failed check
/// (New Scan's availability check, Settings loading status, the sidebar,
/// every screen's mount effect) re-ran the *entire* probe list — the `argus`
/// script, three Python interpreters, two fallback bin paths — from scratch,
/// each spawning its own subprocess. On Windows that's what showed up as a
/// storm of console windows flashing open and closed and the UI feeling stuck
/// while it churned through all of them, repeatedly, on every navigation.
/// `refresh_argus_cli` (called after the user saves a new override path in
/// Settings) resets this to "never probed" so the next call re-checks fresh.
static ARGUS_CACHE: Mutex<Option<Option<ArgusCli>>> = Mutex::new(None);

fn argus_cli() -> Result<ArgusCli, String> {
  {
    let cache = ARGUS_CACHE.lock().unwrap();
    if let Some(cached) = cache.as_ref() {
      return cached.clone().ok_or_else(|| NOT_FOUND_MSG.to_string());
    }
  }
  let found = detect_argus();
  *ARGUS_CACHE.lock().unwrap() = Some(found.clone());
  found.ok_or_else(|| NOT_FOUND_MSG.to_string())
}

/// Force the next `argus_cli()` call to re-probe from scratch instead of
/// reusing a cached result — used after the user saves a new manual path.
fn refresh_argus_cli() {
  *ARGUS_CACHE.lock().unwrap() = None;
}

/// A fresh `Command` for the resolved Argus CLI, with any `-m argus` base args
/// already applied — append the subcommand and flags as usual.
fn argus_command() -> Result<Command, String> {
  let cli = argus_cli()?;
  let mut cmd = new_command(&cli.program);
  cmd.args(&cli.base_args);
  Ok(cmd)
}

/// Runs the real Argus engine against `target` and returns the resulting
/// `report.json` contents. `mode` is "scan" (phase 1 only) or "audit" (phase
/// 1 + phase 2). Resolved via `argus_command`, which normally means the CLI
/// bundled directly inside this app (see `bundled_argus_path`) — this is the
/// desktop shell driving the existing CLI, not a reimplementation of it.
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
    // The GUI has no TTY for the CLI's interactive authorization prompt, and
    // clicking "Strike the app" here *is* the operator's explicit consent
    // gesture — pass the same flag a CI/non-interactive CLI invocation would
    // need, rather than the subprocess silently hanging on stdin forever.
    cmd.args(["audit", &target, "--yes-i-am-authorized"]);
    if let Some(a) = agents.filter(|a| !a.is_empty()) {
      cmd.args(["--agents", &a]);
    }
    cmd.env("ARGUS_EVENT_STREAM", "1");
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| format!("failed to launch argus: {e}"))?;
    *AUDIT_CANCELED.lock().unwrap() = false;
    *AUDIT_CHILD.lock().unwrap() = Some(child.id());

    if let Some(stdout) = child.stdout.take() {
      for line in BufReader::new(stdout).lines().map_while(Result::ok) {
        if let Some(rest) = line.strip_prefix(EVENT_SENTINEL) {
          let _ = window.emit("argus://event", rest.to_string());
        }
      }
    }

    let wait_result = child.wait();
    *AUDIT_CHILD.lock().unwrap() = None;
    let canceled = std::mem::take(&mut *AUDIT_CANCELED.lock().unwrap());
    let status = wait_result.map_err(|e| format!("argus did not finish cleanly: {e}"))?;
    if canceled {
      return Err("Scan canceled.".into());
    }
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

/// Kills the in-progress `argus audit` child started by `run_audit`, if any —
/// the Live Attack screen's Cancel button. A no-op (not an error) when nothing
/// is running, since the frontend may race a scan finishing on its own.
#[tauri::command]
fn cancel_audit() -> Result<(), String> {
  let pid = match *AUDIT_CHILD.lock().unwrap() {
    Some(pid) => pid,
    None => return Ok(()),
  };
  *AUDIT_CANCELED.lock().unwrap() = true;

  #[cfg(target_os = "windows")]
  let result = new_command("taskkill")
    .args(["/PID", &pid.to_string(), "/T", "/F"])
    .output();
  #[cfg(not(target_os = "windows"))]
  let result = new_command("kill")
    .args(["-TERM", &pid.to_string()])
    .output();

  match result {
    Ok(_) => Ok(()),
    Err(e) => Err(format!("failed to cancel: {e}")),
  }
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

/// Persists the local Ollama model to use via `argus config --model <name>` —
/// so Settings can offer a real choice among every model already pulled on
/// this machine, not just the one size-recommended default.
#[tauri::command]
fn set_local_model(name: String) -> Result<(), String> {
  let output = argus_command()?
    .args(["config", "--model", &name])
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

/// Returns the manually-configured Argus CLI path, if the user has set one —
/// so Settings can show what's currently saved.
#[tauri::command]
fn get_argus_path() -> Option<String> {
  read_override()
}

/// Validates and saves a manually-configured Argus CLI path (Settings' escape
/// hatch for when auto-detection can't find it — e.g. a project venv install).
/// Rejects a path that doesn't actually answer `--version` rather than saving
/// something broken and failing confusingly later. On success, invalidates the
/// resolver cache so the new path takes effect immediately, no restart needed.
#[tauri::command]
fn set_argus_path(path: String) -> Result<(), String> {
  let trimmed = path.trim();
  if trimmed.is_empty() {
    return Err("Path can't be empty.".to_string());
  }
  if !probe(trimmed, &[]) {
    return Err(format!("`{trimmed} --version` didn't succeed — check the path points at the argus executable."));
  }
  write_override(trimmed)?;
  refresh_argus_cli();
  Ok(())
}

/// Clears a manually-configured path, falling back to auto-detection again.
#[tauri::command]
fn clear_argus_path() -> Result<(), String> {
  if let Some(file) = override_path_file() {
    if file.exists() {
      std::fs::remove_file(&file).map_err(|e| format!("failed to clear saved path: {e}"))?;
    }
  }
  refresh_argus_cli();
  Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
  tauri::Builder::default()
    .invoke_handler(tauri::generate_handler![
      run_audit, cancel_audit, check_argus_available, read_source_snippet, read_scan_history,
      read_scan_comparison, read_status, set_provider, set_local_model, save_provider_key,
      suppress_finding, get_argus_path, set_argus_path, clear_argus_path
    ])
    .setup(|app| {
      if let Ok(dir) = app.path().resource_dir() {
        let _ = RESOURCE_DIR.set(dir);
      }
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
