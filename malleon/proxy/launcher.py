import os
import subprocess
from pathlib import Path


def launch_binary(
    binary_path: Path,
    proxy_port: int,
    binary_args: list[str] | None = None,
    timeout: int | None = None,
) -> int:
    proxy_url = f"http://127.0.0.1:{proxy_port}"
    env = {
        **os.environ,
        "HTTP_PROXY": proxy_url,
        "HTTPS_PROXY": proxy_url,
        "http_proxy": proxy_url,
        "https_proxy": proxy_url,
    }
    cmd = [str(binary_path)] + (binary_args or [])
    proc = subprocess.Popen(cmd, env=env)
    try:
        return proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.terminate()
        proc.wait()
        return -1
