"""PyInstaller entry point for the bundled Argus CLI.

`argus.cli.main:app` is a Typer application object, not a `def main()`
function — PyInstaller needs a real script with a top-level call, so this
thin shim just invokes it. This is the file PyInstaller's Analysis starts
from (see argus.spec); it is never imported by the rest of the package.
"""

from argus.cli.main import app

if __name__ == "__main__":
    app()
