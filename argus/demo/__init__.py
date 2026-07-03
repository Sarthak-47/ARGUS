"""Bundled, legal-to-attack demo target and sample source.

Ships a self-contained intentionally-vulnerable app so ``argus demo`` can show a
full scan (on the sample source) and a full attack (against the app running
locally) with zero setup — the 30-second "wow". Everything here is deliberately
insecure and must never be used as real code.
"""

from argus.demo.target import SAMPLE_FILES, DemoServer

__all__ = ["SAMPLE_FILES", "DemoServer"]
