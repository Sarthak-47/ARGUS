"""GPU / accelerator detection and local-model recommendation.

Detection order mirrors the spec: nvidia-smi → ROCm (rocm-smi) → Apple Silicon
(unified RAM × 0.75). Falls back to "no GPU" cleanly on machines without one
(e.g. this Windows box), in which case Argus recommends a cloud provider.
"""

from __future__ import annotations

import platform
import re
import shutil
import subprocess
from dataclasses import dataclass

from argus.config.defaults import VRAM_MODEL_MAP


@dataclass
class GPUInfo:
    vendor: str          # "nvidia" | "amd" | "apple" | "none"
    name: str
    vram_gb: float       # usable VRAM in GB (0 when none)

    @property
    def detected(self) -> bool:
        return self.vendor != "none" and self.vram_gb > 0


def _run(cmd: list[str]) -> str | None:
    """Run a command, returning stdout or None if it is missing/fails."""
    if shutil.which(cmd[0]) is None:
        return None
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
        if proc.returncode == 0:
            return proc.stdout
    except (subprocess.SubprocessError, OSError):
        return None
    return None


def _detect_nvidia() -> GPUInfo | None:
    out = _run(["nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader,nounits"])
    if not out:
        return None
    line = out.strip().splitlines()[0] if out.strip() else ""
    if not line:
        return None
    parts = [p.strip() for p in line.split(",")]
    name = parts[0] if parts else "NVIDIA GPU"
    vram_mb = float(parts[1]) if len(parts) > 1 and parts[1].replace(".", "").isdigit() else 0.0
    return GPUInfo("nvidia", name, round(vram_mb / 1024, 1))


def _detect_amd() -> GPUInfo | None:
    out = _run(["rocm-smi", "--showmeminfo", "vram"])
    if not out:
        return None
    m = re.search(r"(\d+)\s*(MB|MiB)", out)
    vram_gb = round(int(m.group(1)) / 1024, 1) if m else 0.0
    return GPUInfo("amd", "AMD GPU (ROCm)", vram_gb)


def _detect_apple() -> GPUInfo | None:
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        return None
    try:
        import psutil

        total_ram_gb = psutil.virtual_memory().total / (1024 ** 3)
    except Exception:
        return None
    # Unified memory: budget ~75% for the model.
    return GPUInfo("apple", f"Apple Silicon ({platform.machine()})", round(total_ram_gb * 0.75, 1))


def detect_gpu() -> GPUInfo:
    """Return the best accelerator found, or a 'none' record."""
    for probe in (_detect_nvidia, _detect_amd, _detect_apple):
        info = probe()
        if info and info.detected:
            return info
    return GPUInfo("none", "No GPU detected", 0.0)


def recommend_model(vram_gb: float) -> str | None:
    """Largest model whose VRAM tier fits within available VRAM."""
    if vram_gb <= 0:
        return None
    best: str | None = None
    for tier in sorted(VRAM_MODEL_MAP):
        if vram_gb >= tier:
            best = VRAM_MODEL_MAP[tier]
        else:
            break
    return best
