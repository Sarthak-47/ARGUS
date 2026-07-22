"""Optional Docker sandbox management.

When Docker is available and the target is a repo (not a live URL), Argus spins
the app up in a container to attack it. Docker is *not* required: this module
detects availability and the pipeline falls back to ``--url`` mode when it's
missing.

Isolation this actually provides: each sandbox run gets its own dedicated
bridge network (not the shared default bridge, so it's cleanly torn down and
never collides with other containers) and a memory cap. It does **not** block
the sandboxed app's outbound network access. An earlier design used Docker's
``internal`` network flag to try to fully lock the container away from the
host — verified empirically (real ``docker network create --internal`` +
``docker run -p`` test) that this also blocks the *host* from reaching the
container's published port, which would defeat the purpose of attacking it.
Full outbound lockdown needs host firewall rules, which is out of scope here;
this module does not claim network isolation it hasn't actually verified.
"""

from __future__ import annotations

import shutil
import socket
import time
import uuid
from pathlib import Path

from argus.sandbox import dockerfile_gen


def docker_available() -> bool:
    """True only if the docker CLI exists and the daemon answers."""
    if shutil.which("docker") is None:
        return False
    try:
        import subprocess

        proc = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True, text=True, timeout=8,
        )
        return proc.returncode == 0
    except (subprocess.SubprocessError, OSError):
        return False


def availability_note() -> str:
    if docker_available():
        return "docker available"
    if shutil.which("docker") is None:
        return "docker not installed — use 'argus attack --url <running-app>' instead"
    return "docker installed but daemon not reachable — start Docker Desktop"


class SandboxError(RuntimeError):
    """Raised when the sandbox can't be built, started, or reached."""


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_until_reachable(url: str, timeout: float) -> bool:
    import httpx

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            httpx.get(url, timeout=2.0)
            return True
        except httpx.HTTPError:
            time.sleep(1.0)
    return False


class Sandbox:
    """Builds and runs a target repo in Docker for the duration of an attack.

    Usage: ``base_url = sandbox.start()`` then always ``sandbox.stop()`` in a
    ``finally`` block — ``start()`` can partially succeed (image built, network
    created) before failing, and ``stop()`` tears down whatever exists.
    """

    def __init__(self, root: Path, llm_provider=None):
        self.root = root
        self._llm_provider = llm_provider
        self._client = None
        self._network = None
        self._container = None
        self._image_id: str | None = None
        self._compose_file: Path | None = None  # set only when running via docker compose
        self._compose_project: str | None = None
        self._llm_guessed = False  # for a clearer error message if this guess fails

    def start(self, timeout: float = 60.0) -> str:
        dockerfile_info = dockerfile_gen.find_existing_dockerfile(self.root) or dockerfile_gen.generate_dockerfile(self.root)
        if dockerfile_info is None:
            # No single-container path — fall back to a docker-compose stack if
            # the repo has one with an explicitly published port. Multi-service
            # repos (a separate frontend/backend, a DB sidecar, …) are exactly
            # what a single generated Dockerfile can't represent.
            compose_info = dockerfile_gen.compose_target(self.root)
            if compose_info is not None:
                return self._start_compose(compose_info, timeout)
            # Last resort: ask the configured LLM to identify the stack and
            # write a Dockerfile itself. Only reached once every deterministic
            # probe has already declined — see the module docstring in
            # dockerfile_gen.py for why a wrong guess here is safe (this
            # function still verifies the container actually becomes
            # reachable below before trusting it).
            dockerfile_info = dockerfile_gen.generate_dockerfile_via_llm(self.root, self._llm_provider)
            if dockerfile_info is not None:
                self._llm_guessed = True
        if dockerfile_info is None:
            raise SandboxError(
                "Couldn't determine how to run this repo automatically (no Dockerfile, no "
                "docker-compose file with a published port, and the stack isn't one Argus "
                "can confidently guess a start command for). Start it yourself and use --url instead."
            )

        try:
            import docker
            from docker.errors import APIError, BuildError, DockerException
        except ImportError as exc:
            raise SandboxError(
                "The 'docker' Python package isn't installed — pip install 'argus-panoptes[sandbox]'."
            ) from exc

        content_or_name, container_port = dockerfile_info
        generated = content_or_name != "Dockerfile"

        try:
            self._client = docker.from_env()
        except DockerException as exc:
            raise SandboxError(f"Docker isn't reachable: {exc}") from exc

        generated_path: Path | None = None
        dockerignore_path: Path | None = None
        dockerignore_original: str | None = None
        try:
            if generated:
                generated_path = self.root / ".argus-sandbox.Dockerfile"
                generated_path.write_text(content_or_name, encoding="utf-8")
                dockerfile_name = generated_path.name
                # A generated Dockerfile's `COPY . .` would otherwise pull the
                # repo's own .git/.env into the image — see the helper's
                # docstring in dockerfile_gen.py. Restored in `finally` no
                # matter what happens below.
                dockerignore_path, dockerignore_original = dockerfile_gen.write_sandbox_dockerignore(self.root)
            else:
                dockerfile_name = "Dockerfile"

            tag = f"argus-sandbox:{uuid.uuid4().hex[:10]}"
            try:
                image, _logs = self._client.images.build(
                    path=str(self.root), dockerfile=dockerfile_name, tag=tag,
                    rm=True, forcerm=True,
                )
            except BuildError as exc:
                raise SandboxError(self._sandbox_error_prefix() + f"Docker build failed: {exc}") from exc
            except APIError as exc:
                raise SandboxError(self._sandbox_error_prefix() + f"Docker build failed: {exc}") from exc
            self._image_id = image.id
        finally:
            if generated_path is not None:
                generated_path.unlink(missing_ok=True)
            if dockerignore_path is not None:
                dockerfile_gen.restore_sandbox_dockerignore(dockerignore_path, dockerignore_original)

        net_name = f"argus-net-{uuid.uuid4().hex[:10]}"
        try:
            self._network = self._client.networks.create(net_name, driver="bridge")
        except APIError as exc:
            raise SandboxError(f"Could not create sandbox network: {exc}") from exc

        host_port = _free_port()
        try:
            self._container = self._client.containers.run(
                tag, detach=True, network=net_name,
                # A bare int port spec here binds 0.0.0.0 — every interface,
                # not just this machine's loopback — for as long as the
                # sandbox runs. The (bind_ip, port) tuple form is what
                # actually restricts it to 127.0.0.1, matching what base_url
                # below already assumes.
                ports={f"{container_port}/tcp": ("127.0.0.1", host_port)},
                mem_limit="512m", security_opt=["no-new-privileges"],
            )
        except APIError as exc:
            raise SandboxError(f"Could not start sandbox container: {exc}") from exc

        base_url = f"http://127.0.0.1:{host_port}"
        if not _wait_until_reachable(base_url, timeout=timeout):
            raise SandboxError(
                self._sandbox_error_prefix()
                + f"The sandboxed app never became reachable at {base_url} within "
                f"{timeout:.0f}s (check the generated Dockerfile / the app's start command)."
            )
        return base_url

    def _sandbox_error_prefix(self) -> str:
        """Distinguishes an LLM-guessed Dockerfile's failure from a
        deterministically-generated one's in the error message — the fix is
        different (the LLM guessed wrong stack/entry point vs. a real bug in
        one of Argus's own hardcoded templates)."""
        return "LLM-guessed Dockerfile didn't work — " if self._llm_guessed else ""

    def _start_compose(self, compose_info: tuple[Path, int], timeout: float) -> str:
        import subprocess

        compose_file, host_port = compose_info
        if not self._compose_available():
            raise SandboxError(
                "Found a docker-compose file, but the 'docker compose' plugin isn't "
                "available. Start the stack yourself and use --url instead."
            )
        self._compose_file = compose_file
        # Never reuse the repository directory's default Compose project name:
        # doing so could attach to, or tear down, a developer's existing stack.
        self._compose_project = f"argus-{uuid.uuid4().hex[:10]}"
        try:
            subprocess.run(
                ["docker", "compose", "--project-name", self._compose_project,
                 "-f", str(compose_file), "up", "-d", "--build"],
                cwd=str(self.root), capture_output=True, text=True, timeout=300, check=True,
            )
        except subprocess.CalledProcessError as exc:
            raise SandboxError(f"docker compose up failed: {(exc.stderr or exc.stdout or '').strip()[:500]}") from exc
        except subprocess.SubprocessError as exc:
            raise SandboxError(f"docker compose up failed: {exc}") from exc

        base_url = f"http://127.0.0.1:{host_port}"
        if not _wait_until_reachable(base_url, timeout=timeout):
            raise SandboxError(
                f"The compose stack never became reachable at {base_url} within "
                f"{timeout:.0f}s (check the compose file's build/service definitions)."
            )
        return base_url

    @staticmethod
    def _compose_available() -> bool:
        import subprocess

        try:
            proc = subprocess.run(["docker", "compose", "version"], capture_output=True, text=True, timeout=8)
            return proc.returncode == 0
        except (subprocess.SubprocessError, OSError):
            return False

    def stop(self) -> None:
        if self._compose_file is not None:
            import subprocess

            try:
                subprocess.run(
                    ["docker", "compose", "--project-name", self._compose_project or "argus",
                     "-f", str(self._compose_file), "down", "-v"],
                    cwd=str(self.root), capture_output=True, text=True, timeout=120,
                )
            except (subprocess.SubprocessError, OSError):
                pass
            return
        if self._container is not None:
            try:
                self._container.remove(force=True)
            except Exception:
                pass
        if self._network is not None:
            try:
                self._network.remove()
            except Exception:
                pass
        if self._image_id is not None and self._client is not None:
            try:
                self._client.images.remove(self._image_id, force=True)
            except Exception:
                pass
