"""Windows-specific CA certificate and proxy setup utilities for malleon."""
from __future__ import annotations

import shutil
import subprocess
import sys
import time
from pathlib import Path

try:
    import winreg as _winreg  # available on Windows only
except ImportError:
    _winreg = None  # type: ignore[assignment]

# Registry key that Windows Settings > Proxy writes to
_INET_SETTINGS_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
_INET_PROXY_NAMES = ("ProxyEnable", "ProxyServer", "ProxyOverride")

# Saved WinINet state so reset_wininet_proxy() can restore it exactly
_wininet_saved: dict | None = None

_CA_PEM = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"


def ensure_ca_cert() -> Path:
    """Return the mitmproxy CA cert path, generating it if absent."""
    if _CA_PEM.exists():
        return _CA_PEM
    print("mitmproxy CA certificate not found - generating…", flush=True)
    _generate_ca_cert(_CA_PEM)
    if not _CA_PEM.exists():
        raise RuntimeError(
            f"mitmproxy CA was not created at {_CA_PEM}. "
            "Run 'mitmdump' once manually to initialise the certificate store."
        )
    return _CA_PEM


def _generate_ca_cert(pem_path: Path) -> None:
    """Start mitmdump briefly on a temporary port to trigger CA cert generation."""
    mitmdump = shutil.which("mitmdump")
    if mitmdump is None:
        # Common location when installed in a venv next to the Python binary
        candidate = Path(sys.executable).parent / "mitmdump.exe"
        if candidate.exists():
            mitmdump = str(candidate)
    if mitmdump is None:
        raise RuntimeError(
            "mitmdump not found on PATH; cannot generate the CA certificate automatically."
        )
    proc = subprocess.Popen(
        [mitmdump, "-p", "18081"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + 10.0
    while not pem_path.exists() and time.monotonic() < deadline:
        time.sleep(0.2)
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()


def is_ca_installed() -> bool:
    """Return True if the mitmproxy CA cert is present in the Windows ROOT store."""
    if sys.platform != "win32":
        return False
    try:
        result = subprocess.run(
            ["certutil", "-store", "ROOT"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        return "mitmproxy" in result.stdout.lower()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def is_proxy_configured(port: int) -> bool:
    """Return True if WinHTTP is already configured to proxy via 127.0.0.1:<port>."""
    if sys.platform != "win32":
        return False
    try:
        result = subprocess.run(
            ["netsh", "winhttp", "show", "proxy"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return f"127.0.0.1:{port}" in result.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def install_ca_cert(pem_path: Path) -> None:
    """Install the mitmproxy CA certificate in the Windows ROOT store if not already present."""
    if sys.platform != "win32":
        return
    if is_ca_installed():
        return

    try:
        result = subprocess.run(
            ["certutil", "-addstore", "-f", "ROOT", str(pem_path)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            print("mitmproxy CA certificate installed in Windows ROOT store.", flush=True)
        else:
            print(
                f"warning: CA certificate installation failed "
                f"(certutil exit {result.returncode}). "
                "Run malleon as Administrator to install it, or pass --no-system-proxy.",
                file=sys.stderr,
                flush=True,
            )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        print(f"warning: CA certificate installation skipped ({exc}).", file=sys.stderr, flush=True)


def set_system_proxy(port: int) -> None:
    """Set the WinHTTP system proxy to 127.0.0.1:<port>."""
    if sys.platform != "win32":
        return
    try:
        subprocess.run(
            ["netsh", "winhttp", "set", "proxy", f"127.0.0.1:{port}"],
            capture_output=True,
            check=True,
            timeout=10,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as exc:
        print(f"warning: could not set WinHTTP proxy ({exc}).", file=sys.stderr, flush=True)


def reset_system_proxy() -> None:
    """Reset WinHTTP proxy to direct (no proxy)."""
    if sys.platform != "win32":
        return
    try:
        subprocess.run(
            ["netsh", "winhttp", "reset", "proxy"],
            capture_output=True,
            check=True,
            timeout=10,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as exc:
        print(f"warning: could not reset WinHTTP proxy ({exc}).", file=sys.stderr, flush=True)


def _find_mitmproxy_thumbprint(output: str) -> str | None:
    """Parse certutil output and return the SHA-1 thumbprint of the mitmproxy certificate."""
    for block in output.split("================"):
        if "mitmproxy" not in block.lower():
            continue
        for line in block.splitlines():
            lower = line.lower()
            if "hash(sha1)" in lower or "cert hash" in lower:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    thumbprint = parts[1].replace(" ", "").strip()
                    if thumbprint:
                        return thumbprint
    return None


def uninstall_ca_cert() -> None:
    """Remove the mitmproxy CA certificate from the Windows ROOT store."""
    if sys.platform != "win32":
        return
    try:
        store_result = subprocess.run(
            ["certutil", "-store", "ROOT"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        thumbprint = _find_mitmproxy_thumbprint(store_result.stdout)
        if thumbprint is None:
            print("mitmproxy CA certificate not found in ROOT store - nothing to remove.")
            return
        del_result = subprocess.run(
            ["certutil", "-delstore", "ROOT", thumbprint],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if del_result.returncode == 0:
            print("mitmproxy CA certificate removed from Windows ROOT store.", flush=True)
        else:
            print(
                f"warning: failed to remove CA certificate "
                f"(certutil exit {del_result.returncode}). "
                "Run malleon cleanup as Administrator.",
                file=sys.stderr,
                flush=True,
            )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        print(f"warning: CA certificate removal skipped ({exc}).", file=sys.stderr, flush=True)


def set_wininet_proxy(port: int) -> None:
    """Configure the WinINet proxy registry settings to route through the given port."""
    if sys.platform != "win32":
        return

    global _wininet_saved
    saved: dict = {}

    # ---- read and save current state ----
    try:
        read_key = _winreg.OpenKey(
            _winreg.HKEY_CURRENT_USER,
            _INET_SETTINGS_KEY,
            access=_winreg.KEY_READ,
        )
        for name in _INET_PROXY_NAMES:
            try:
                value, reg_type = _winreg.QueryValueEx(read_key, name)
                saved[name] = (value, reg_type)
            except OSError:
                saved[name] = None  # value didn't exist before setup
        _winreg.CloseKey(read_key)
    except OSError:
        # Key path itself is absent (treat all values as non-existent)
        for name in _INET_PROXY_NAMES:
            saved[name] = None

    _wininet_saved = saved
    print("WinINet: saved existing proxy settings.", flush=True)

    # ---- write new proxy settings ----
    try:
        write_key = _winreg.OpenKey(
            _winreg.HKEY_CURRENT_USER,
            _INET_SETTINGS_KEY,
            access=_winreg.KEY_WRITE,
        )
        _winreg.SetValueEx(write_key, "ProxyEnable", 0, _winreg.REG_DWORD, 1)
        print("WinINet: set ProxyEnable = 1.", flush=True)
        _winreg.SetValueEx(write_key, "ProxyServer", 0, _winreg.REG_SZ, f"127.0.0.1:{port}")
        print(f"WinINet: set ProxyServer = 127.0.0.1:{port}.", flush=True)
        _winreg.SetValueEx(write_key, "ProxyOverride", 0, _winreg.REG_SZ, "")
        print('WinINet: set ProxyOverride = "".', flush=True)
        _winreg.CloseKey(write_key)
    except OSError as exc:
        print(f"warning: could not configure WinINet proxy ({exc}).", file=sys.stderr, flush=True)


def reset_wininet_proxy() -> None:
    """Restore WinINet proxy settings to their state before set_wininet_proxy was called."""
    if sys.platform != "win32":
        return

    if _wininet_saved is None:
        print("WinINet: no saved state found; using safe defaults.", flush=True)
        fallback: dict = {
            "ProxyEnable": (0, _winreg.REG_DWORD),
            "ProxyServer": None,
            "ProxyOverride": None,
        }
        saved = fallback
    else:
        saved = _wininet_saved

    try:
        write_key = _winreg.OpenKey(
            _winreg.HKEY_CURRENT_USER,
            _INET_SETTINGS_KEY,
            access=_winreg.KEY_WRITE,
        )
        for name, prev in saved.items():
            if prev is None:
                # Value didn't exist before setup (remove it)
                try:
                    _winreg.DeleteValue(write_key, name)
                    print(f"WinINet: deleted {name}.", flush=True)
                except OSError:
                    pass  # already absent
            else:
                value, reg_type = prev
                _winreg.SetValueEx(write_key, name, 0, reg_type, value)
                print(f"WinINet: restored {name} = {value!r}.", flush=True)
        _winreg.CloseKey(write_key)
    except OSError as exc:
        print(
            f"warning: could not restore WinINet proxy settings ({exc}).",
            file=sys.stderr,
            flush=True,
        )
