import asyncio
import base64
import threading

from mitmproxy import http, options
from mitmproxy.tools.dump import DumpMaster


class _CaptureAddon:
    def __init__(self, ready: threading.Event) -> None:
        self._ready = ready
        self.flows: list[dict] = []

    def running(self) -> None:
        self._ready.set()

    def response(self, flow: http.HTTPFlow) -> None:
        self.flows.append(_serialize_flow(flow))


def _serialize_flow(flow: http.HTTPFlow) -> dict:
    req = flow.request
    resp = flow.response
    return {
        "request": {
            "method": req.method,
            "scheme": req.scheme,
            "host": req.host,
            "port": req.port,
            "path": req.path,
            "http_version": req.http_version,
            "headers": list(req.headers.items()),
            "body": _encode_body(req.content),
        },
        "response": {
            "http_version": resp.http_version,
            "status_code": resp.status_code,
            "reason": resp.reason,
            "headers": list(resp.headers.items()),
            "body": _encode_body(resp.content),
        }
        if resp
        else None,
        "timestamp_start": flow.request.timestamp_start,
    }


def _encode_body(content: bytes | None) -> dict | None:
    if not content:
        return None
    try:
        return {"encoding": "utf-8", "data": content.decode("utf-8")}
    except UnicodeDecodeError:
        return {"encoding": "base64", "data": base64.b64encode(content).decode("ascii")}


class ProxyRunner:
    def __init__(self, port: int) -> None:
        self._port = port
        self._ready = threading.Event()
        self._addon = _CaptureAddon(self._ready)
        self._master: DumpMaster | None = None
        self._thread: threading.Thread | None = None

    def start(self, startup_timeout: float = 10.0) -> None:
        self._thread = threading.Thread(target=self._run, daemon=True, name="mitmproxy")
        self._thread.start()
        if not self._ready.wait(timeout=startup_timeout):
            raise RuntimeError(f"Proxy did not start within {startup_timeout}s on port {self._port}")

    def stop(self) -> None:
        if self._master:
            self._master.shutdown()
        if self._thread:
            self._thread.join(timeout=5)

    @property
    def flows(self) -> list[dict]:
        return list(self._addon.flows)

    def _run(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        async def _async_run() -> None:
            opts = options.Options(listen_port=self._port, ssl_insecure=True)
            self._master = DumpMaster(opts, with_termlog=False, with_dumper=False)
            self._master.addons.add(self._addon)
            await self._master.run()

        loop.run_until_complete(_async_run())
