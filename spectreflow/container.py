import os
import sys
import shutil
import subprocess
import tempfile
import logging

import psutil
import config

logger = logging.getLogger("spectreflow.container")

_SCRIPT_EXTENSIONS = {".py", ".pyw"}


class Container:
    def __init__(self, target_path: str, timeout: float = None):
        self.original_path = os.path.abspath(target_path)
        self.timeout = timeout or config.CONTAINER_TIMEOUT
        self.sandbox_dir = None
        self.sandbox_target = None
        self.process = None

    def setup(self) -> str:
        self.sandbox_dir = tempfile.mkdtemp(prefix="spectreflow_sandbox_")
        filename = os.path.basename(self.original_path)
        self.sandbox_target = os.path.join(self.sandbox_dir, filename)
        shutil.copy2(self.original_path, self.sandbox_target)

        logger.info("Sandbox created: %s", self.sandbox_dir)
        logger.info("Target copied: %s → %s", self.original_path, self.sandbox_target)
        return self.sandbox_target

    def launch(self) -> subprocess.Popen:
        _, ext = os.path.splitext(self.sandbox_target)
        if ext.lower() in _SCRIPT_EXTENSIONS:
            cmd = [sys.executable, self.sandbox_target]
        else:
            cmd = [self.sandbox_target]

        self.process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=self.sandbox_dir,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
        )

        logger.info("Target launched in sandbox — PID %d", self.process.pid)
        return self.process

    def kill(self):
        if not self.process:
            return
        pid = self.process.pid
        try:
            parent = psutil.Process(pid)
            children = parent.children(recursive=True)
            for child in children:
                logger.info("Killing child process: %s (PID %d)", child.name(), child.pid)
                child.kill()
            psutil.wait_procs(children, timeout=5)
            parent.kill()
            parent.wait(timeout=5)
            logger.info("Target process tree killed (root PID %d, %d children)", pid, len(children))
        except psutil.NoSuchProcess:
            logger.info("Process %d already exited", pid)

    def teardown(self):
        self.kill()
        if self.sandbox_dir and os.path.isdir(self.sandbox_dir):
            artifacts = os.listdir(self.sandbox_dir)
            if len(artifacts) > 1:
                logger.info("Sandbox artifacts before cleanup: %s", artifacts)
            shutil.rmtree(self.sandbox_dir, ignore_errors=True)
            logger.info("Sandbox destroyed: %s", self.sandbox_dir)
            self.sandbox_dir = None
