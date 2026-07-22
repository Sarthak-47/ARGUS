use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
  // A unique id per build, baked into the binary. Each release is a fresh
  // clean build in CI, so every installer carries a distinct value — that's
  // what lets the app tell a fresh install apart from a relaunch of the same
  // one (see init_install_marker in lib.rs) and start Recent Scans empty on a
  // reinstall even though scan history persists in ~/.argus.
  let build_id = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .map(|d| d.as_secs())
    .unwrap_or(0);
  println!("cargo:rustc-env=ARGUS_BUILD_ID={build_id}");
  tauri_build::build()
}
