"""Enable ``python -m argus`` as an equivalent to the ``argus`` console script.

The desktop app (and any environment where the ``argus`` entry-point script
isn't on PATH — e.g. a GUI launched from the Dock/Start menu, which doesn't
inherit the shell PATH) can fall back to ``python -m argus``.
"""

from argus.cli.main import app

if __name__ == "__main__":
    app()
