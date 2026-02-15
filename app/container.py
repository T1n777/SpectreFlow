import io
import json
import os
import signal
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import logging

import psutil

try:
    import docker
    _HAS_DOCKER = True
except ImportError:
    _HAS_DOCKER = False

import config

logger = logging.getLogger("spectreflow.container")

_AGENT_PATH = os.path.join(os.path.dirname(__file__), "sandbox_agent.py")
_SANDBOX_TAG = "spectreflow-sandbox:latest"
_SCRIPT_EXTENSIONS = {".py", ".pyw"}
_WINDOWS_EXTENSIONS = {".exe", ".dll", ".bat", ".cmd", ".msi", ".scr", ".pif"}

_DOCKERFILE = """\
FROM {base}
RUN pip install --no-cache-dir psutil
WORKDIR /sandbox
"""


def get_sandbox(target_path: str, docker_image: str = None):
    _, ext = os.path.splitext(target_path)
    if ext.lower() in _WINDOWS_EXTENSIONS:
        logger.info("Windows target detected — using local sandbox.")
        return LocalSandbox()
    if not _HAS_DOCKER:
        logger.info("docker package not installed — falling back to local sandbox.")
        return LocalSandbox()
    logger.info("Script target detected — using Docker sandbox.")
    return DockerSandbox(image=docker_image)


class LocalSandbox:
    def __init__(self):
        self.sandbox_dir = None
        self.sandbox_target = None
        self.process = None
        self._killed = False
        self._watchdog = None

    def setup(self):
        pass

    def launch(self, target_path: str, duration: float = None):
        duration = duration or config.CONTAINER_TIMEOUT
        abs_target = os.path.abspath(target_path)
        self.sandbox_dir = tempfile.mkdtemp(prefix="spectreflow_sandbox_")
        filename = os.path.basename(abs_target)
        self.sandbox_target = os.path.join(self.sandbox_dir, filename)
        shutil.copy2(abs_target, self.sandbox_target)

        logger.info("Sandbox created: %s", self.sandbox_dir)

        _, ext = os.path.splitext(self.sandbox_target)
        if ext.lower() in _SCRIPT_EXTENSIONS:
            cmd = [sys.executable, self.sandbox_target]
        else:
            cmd = [self.sandbox_target]

        popen_kwargs = dict(
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=self.sandbox_dir,
        )
        if os.name == "nt":
            popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            popen_kwargs["preexec_fn"] = os.setpgrp

        try:
            self.process = subprocess.Popen(cmd, **popen_kwargs)
        except OSError as e:
            if getattr(e, "winerror", 0) == 740:
                logger.error("Target requires elevation! Run SpectreFlow as Administrator.")
                raise RuntimeError("Target requires Admin privileges. Run SpectreFlow as Administrator.") from e
            raise
        logger.info("Target launched in sandbox — PID %d", self.process.pid)

        self._watchdog = threading.Timer(duration + 2, self._watchdog_kill)
        self._watchdog.daemon = True
        self._watchdog.start()

        return self.process

    def get_pid(self):
        if self.process:
            return self.process.pid
        return None

    def _watchdog_kill(self):
        if not self._killed:
            logger.warning("Watchdog triggered — force-killing process tree.")
            self.kill()

    def kill(self):
        if self._killed or not self.process:
            return
        self._killed = True
        pid = self.process.pid

        if os.name == "nt":
            try:
                result = subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(pid)],
                    capture_output=True, text=True, timeout=10,
                )
                if result.returncode == 0:
                    logger.info("taskkill: process tree killed (PID %d)", pid)
                else:
                    logger.warning("taskkill stderr: %s", result.stderr.strip())
            except Exception as exc:
                logger.warning("taskkill failed: %s — falling back to psutil", exc)
                try:
                    parent = psutil.Process(pid)
                    for child in parent.children(recursive=True):
                        child.kill()
                    parent.kill()
                except psutil.NoSuchProcess:
                    pass
        else:
            # Linux: kill the entire process group
            try:
                os.killpg(os.getpgid(pid), signal.SIGKILL)
                logger.info("killpg: process group killed (PID %d)", pid)
            except (ProcessLookupError, PermissionError) as exc:
                logger.warning("killpg failed: %s — falling back to psutil", exc)
                try:
                    parent = psutil.Process(pid)
                    for child in parent.children(recursive=True):
                        child.kill()
                    parent.kill()
                except psutil.NoSuchProcess:
                    pass

        try:
            self.process.wait(timeout=5)
        except Exception:
            pass
        logger.info("Process tree terminated (PID %d)", pid)

    def teardown(self):
        if self._watchdog:
            self._watchdog.cancel()
        self.kill()
        if self.sandbox_dir and os.path.isdir(self.sandbox_dir):
            shutil.rmtree(self.sandbox_dir, ignore_errors=True)
            logger.info("Sandbox destroyed: %s", self.sandbox_dir)
            self.sandbox_dir = None


class DockerSandbox:
    def __init__(self, image: str = None):
        self.base_image = image or config.DOCKER_IMAGE
        self.client = docker.from_env()
        self.container = None
        self._result = None

    def setup(self):
        try:
            self.client.images.get(_SANDBOX_TAG)
            logger.info("Sandbox image '%s' found locally.", _SANDBOX_TAG)
            return
        except docker.errors.ImageNotFound:
            pass

        logger.info("Building sandbox image from '%s'...", self.base_image)
        dockerfile_content = _DOCKERFILE.format(base=self.base_image).encode("utf-8")

        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            df_info = tarfile.TarInfo(name="Dockerfile")
            df_info.size = len(dockerfile_content)
            tar.addfile(df_info, io.BytesIO(dockerfile_content))
        buf.seek(0)

        image, build_logs = self.client.images.build(
            fileobj=buf, custom_context=True, tag=_SANDBOX_TAG, rm=True
        )
        for chunk in build_logs:
            if "stream" in chunk:
                line = chunk["stream"].strip()
                if line:
                    logger.debug("[build] %s", line)
        logger.info("Sandbox image built: %s", _SANDBOX_TAG)

    def launch(self, target_path: str, duration: float = None):
        duration = duration or config.CONTAINER_TIMEOUT
        abs_target = os.path.abspath(target_path)
        target_name = os.path.basename(abs_target)

        logger.info("Creating container from '%s'...", _SANDBOX_TAG)
        self.container = self.client.containers.create(
            _SANDBOX_TAG,
            command=["python3", "/sandbox/sandbox_agent.py",
                     f"/sandbox/{target_name}", "--duration", str(duration)],
            working_dir="/sandbox",
            network_mode="none",
            mem_limit="512m",
            cpu_period=100000,
            cpu_quota=80000,
            pids_limit=128,
            tty=False,
            detach=True,
        )
        logger.info("Container created: %s", self.container.short_id)

        archive = self._build_archive(abs_target, target_name)
        self.container.put_archive("/sandbox", archive)
        logger.info("Copied agent + target into container.")

        self.container.start()
        logger.info("Container started — running analysis for %ss...", duration)

        wait_timeout = duration + 30
        try:
            result = self.container.wait(timeout=wait_timeout)
            logger.info("Container exited with status %s", result.get("StatusCode"))
        except Exception:
            logger.warning("Container did not exit in time, forcing stop.")
            self.container.stop(timeout=5)

    def _build_archive(self, target_path: str, target_name: str) -> bytes:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            tar.add(_AGENT_PATH, arcname="sandbox_agent.py")
            tar.add(target_path, arcname=target_name)
        buf.seek(0)
        return buf.read()

    def get_results(self) -> dict:
        if not self.container:
            return self._empty()
        logs = self.container.logs(stdout=True, stderr=False).decode("utf-8", errors="replace")
        for line in reversed(logs.strip().splitlines()):
            line = line.strip()
            if line.startswith("{"):
                try:
                    self._result = json.loads(line)
                    return self._result
                except json.JSONDecodeError:
                    continue
        logger.warning("No JSON result found in container logs.")
        stderr = self.container.logs(stdout=False, stderr=True).decode("utf-8", errors="replace")
        if stderr.strip():
            logger.warning("Container stderr:\n%s", stderr[:500])
        return self._empty()

    def get_logs(self) -> str:
        if not self.container:
            return ""
        return self.container.logs(stdout=True, stderr=True).decode("utf-8", errors="replace")

    def teardown(self):
        if not self.container:
            return
        cid = self.container.short_id
        try:
            self.container.stop(timeout=5)
        except Exception:
            pass
        try:
            self.container.remove(force=True)
            logger.info("Container %s removed.", cid)
        except Exception:
            logger.warning("Failed to remove container %s", cid)
        self.container = None

    @staticmethod
    def _empty():
        return {
            "suspicious": False,
            "target_location": None,
            "network_activity": [],
            "suspicious_connections": [],
            "file_activity": [],
            "suspicious_file_write": False,
            "sensitive_dir_write": False,
            "cpu_spike": False,
            "flagged_functions": [],
        }
