; NSIS installer hooks for the Argus desktop app.
;
; The bundled Argus CLI ships as a PyInstaller *onedir* under
; "$INSTDIR\argus-cli". Its "*.dist-info" directory is named with the release
; version, and the default NSIS upgrade overlays new files onto the old install
; without removing files that no longer exist in the new version. So an in-place
; upgrade left the previous version's "argus_panoptes-<old>.dist-info" orphaned
; next to the new one, and importlib.metadata then resolved the STALE version in
; `argus --version` and in every SBOM/VEX tool-version field.
;
; Wipe the CLI resource directory before laying down the new bundle, so every
; upgrade gets a clean onedir with exactly one dist-info. Scoped to argus-cli
; only — user data lives in %USERPROFILE%\.argus and is never touched here.
!macro NSIS_HOOK_PREINSTALL
  RMDir /r "$INSTDIR\argus-cli"
!macroend
