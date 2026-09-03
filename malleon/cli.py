import argparse
import sys
from pathlib import Path

from malleon.proxy.capture import ProxyRunner
from malleon.proxy.intermediate import write_intermediate
from malleon.proxy.launcher import launch_binary


def main() -> None:
    parser = argparse.ArgumentParser(prog="malleon")
    sub = parser.add_subparsers(dest="command", required=True)

    cap = sub.add_parser("capture", help="Run a binary and capture its HTTP/HTTPS traffic")
    cap.add_argument("-o", "--output", type=Path, required=True, help="Output JSON file")
    cap.add_argument("-p", "--port", type=int, default=8080, help="Local proxy port (default: 8080)")
    cap.add_argument("--timeout", type=int, default=None, metavar="SECONDS",
                     help="Kill the binary after this many seconds")
    cap.add_argument("binary_cmd", nargs=argparse.REMAINDER,
                     help="Binary and its arguments (use -- to separate from malleon flags)")

    bld = sub.add_parser(
        "build",
        help="Populate a Malleable C2 profile from captured flows",
        description=(
            "Reads traffic fields (URIs, headers, user-agent) from a captured flows JSON produced by "
            "'malleon capture' and writes them into the base profile, leaving "
            "all operator settings (sleep, jitter, staging, process injection) untouched."
        ),
    )
    bld.add_argument(
        "flows_json",
        type=Path,
        metavar="FLOWS_JSON",
        help="Captured flows JSON (output of 'malleon capture')",
    )
    bld.add_argument(
        "--profile",
        type=Path,
        required=True,
        metavar="BASE_PROFILE",
        help="Base Malleable C2 profile to populate",
    )
    bld.add_argument(
        "-o", "--output",
        type=Path,
        required=True,
        metavar="OUTPUT_PROFILE",
        help="Path for the populated output profile",
    )
    bld.add_argument(
        "--target-domain",
        default=None,
        metavar="DOMAIN",
        help="Only use flows from this host for profile population",
    )
    bld.add_argument(
        "-i", "--id",
        default=None,
        metavar="INDICES",
        help=(
            "Comma-separated 1-based flow indices to use (e.g. 1,3,12). "
            "Mutually exclusive with --target-domain."
        ),
    )
    bld.add_argument(
        "--body-camouflage",
        action="store_true",
        help=(
            "Use the captured response body to hide C2 data inside http-get.server "
            "and http-post.server output blocks (prepend + append around beacon data)."
        ),
    )
    bld.add_argument(
        "--body-split",
        type=int,
        default=128,
        metavar="N",
        help="Bytes of the response body to use as prepend (first N) and append (last N). Default: 128.",
    )
    bld.add_argument(
        "--force-body-camouflage",
        action="store_true",
        help=(
            "Like --body-camouflage but also replaces any existing 'output' block the "
            "operator has already defined in the base profile."
        ),
    )

    run = sub.add_parser(
        "run",
        help="Capture traffic and populate a profile in one step (no intermediate file)",
        description=(
            "Runs a binary under the proxy, captures its traffic in memory, and "
            "immediately populates the base profile - equivalent to 'capture' followed "
            "by 'build' but without writing a flows JSON file to disk."
        ),
    )
    run.add_argument("binary_cmd", nargs=argparse.REMAINDER,
                     help="Binary and its arguments (use -- to separate from malleon flags)")
    run.add_argument(
        "--profile",
        type=Path,
        required=True,
        metavar="BASE_PROFILE",
        help="Base Malleable C2 profile to populate",
    )
    run.add_argument(
        "-o", "--output",
        type=Path,
        required=True,
        metavar="OUTPUT_PROFILE",
        help="Path for the populated output profile",
    )
    run.add_argument("-p", "--port", type=int, default=8080,
                     help="Local proxy port (default: 8080)")
    run.add_argument("--timeout", type=int, default=None, metavar="SECONDS",
                     help="Kill the binary after this many seconds")
    run.add_argument(
        "--target-domain",
        default=None,
        metavar="DOMAIN",
        help="Only use flows from this host for profile population",
    )
    run.add_argument(
        "--body-camouflage",
        action="store_true",
        help=(
            "Use the captured response body to hide C2 data inside http-get.server "
            "and http-post.server output blocks (prepend + append around beacon data)."
        ),
    )
    run.add_argument(
        "--body-split",
        type=int,
        default=128,
        metavar="N",
        help="Bytes of the response body to use as prepend (first N) and append (last N). Default: 128.",
    )
    run.add_argument(
        "--force-body-camouflage",
        action="store_true",
        help=(
            "Like --body-camouflage but also replaces any existing 'output' block the "
            "operator has already defined in the base profile."
        ),
    )

    insp = sub.add_parser(
        "inspect",
        help="Display a summary table of captured flows",
        description="Prints a numbered flow table and a domain frequency summary.",
    )
    insp.add_argument("flows_json", type=Path, metavar="FLOWS_JSON",
                      help="Captured flows JSON to inspect")
    insp.add_argument(
        "--show-id",
        default=None,
        metavar="INDICES",
        help="Comma-separated 1-based flow indices to display as raw HTTP dumps",
    )
    insp.add_argument(
        "-m", "--method",
        default=None,
        metavar="METHOD",
        help="Filter table to flows with this HTTP method (case-insensitive)",
    )
    insp.add_argument(
        "-d", "--domain",
        default=None,
        metavar="DOMAIN",
        help="Filter table to flows from this host (case-insensitive)",
    )

    setup_p = sub.add_parser(
        "setup",
        help="One-time admin setup: generate CA cert, install in ROOT store, configure WinHTTP proxy",
        description=(
            "Generates the mitmproxy CA certificate if absent, installs it in the Windows "
            "ROOT store, and sets the WinHTTP proxy.  Run once as Administrator; subsequent "
            "'malleon run' and 'malleon capture' invocations detect the existing setup and "
            "skip the admin-required steps automatically."
        ),
    )
    setup_p.add_argument("-p", "--port", type=int, default=8080,
                         help="Proxy port to configure in WinHTTP (default: 8080)")

    cleanup_p = sub.add_parser(
        "cleanup",
        help="Undo 'malleon setup': remove mitmproxy CA cert from ROOT store and reset WinHTTP proxy",
        description=(
            "Removes the mitmproxy CA certificate from the Windows ROOT store and resets "
            "the WinHTTP proxy to direct.  Requires Administrator privileges."
        ),
    )
    cleanup_p.add_argument("-p", "--port", type=int, default=8080,
                           help="Proxy port (informational; not used during cleanup)")

    args = parser.parse_args()
    if args.command == "capture":
        _cmd_capture(args)
    elif args.command == "build":
        _cmd_build(args)
    elif args.command == "run":
        _cmd_run(args)
    elif args.command == "setup":
        _cmd_setup(args)
    elif args.command == "inspect":
        _cmd_inspect(args)
    elif args.command == "cleanup":
        _cmd_cleanup(args)


def _warn_header_size(
    block_label: str,
    headers: list[tuple[str, str]],
    limit: int,
    limit_display: str,
) -> None:
    """Warn to stderr when the total serialized size of the header list exceeds the byte limit."""
    total = sum(len(name) + len(value) + 4 for name, value in headers)
    if total > limit:
        print(
            f"warning: {block_label} size is ~{total} bytes.\n"
            f"         May exceed the limit allowed by Cobalt Strike (typically {limit_display}).\n"
            "         Remove headers manually from the output profile before production.",
            file=sys.stderr,
        )


def _warn_uri_length(block_label: str, uri: str, limit: int = 63) -> None:
    """Warn to stderr when a URI exceeds the byte length limit."""
    n = len(uri.encode("utf-8"))
    if n > limit:
        print(
            f"warning: {block_label} '{uri}' is ~{n} bytes.\n"
            f"         May exceed the limit allowed by Cobalt Strike (typically ~{limit} bytes max).\n"
            "         Shorten the URI manually in the output profile before production.",
            file=sys.stderr,
        )


def _cmd_build(args: argparse.Namespace) -> None:
    from malleon.parser.http_extractor import extract_from_file
    from malleon.profile.builder import populate

    if getattr(args, "id", None) is not None and args.target_domain is not None:
        print(
            "error: --id/-i and --target-domain are mutually exclusive.\n"
            "       Use --id/-i to select specific flows by index, or --target-domain to filter by domain, not both.",
            file=sys.stderr,
        )
        sys.exit(2)

    if not args.flows_json.exists():
        print(f"error: flows file not found: {args.flows_json}", file=sys.stderr)
        sys.exit(2)
    if not args.profile.exists():
        print(f"error: base profile not found: {args.profile}", file=sys.stderr)
        sys.exit(2)

    ids: list[int] | None = None
    if getattr(args, "id", None) is not None:
        ids = [int(x.strip()) for x in args.id.split(",") if x.strip()]

    _bc    = getattr(args, "body_camouflage",       False)
    _fbc   = getattr(args, "force_body_camouflage", False)
    _split = getattr(args, "body_split",            128)
    camouflage = _bc or _fbc
    try:
        traffic = extract_from_file(
            args.flows_json,
            target_domain=args.target_domain,
            body_camouflage=camouflage,
            body_split=_split,
            ids=ids,
        )
    except ValueError as e:
        print(str(e), file=sys.stderr)
        sys.exit(2)
    populate(
        args.profile, traffic, args.output,
        body_camouflage=_bc,
        force_body_camouflage=_fbc,
    )
    # Warn when client header blocks approach Cobalt Strike's size limits.
    if traffic.http_get is not None:
        _warn_header_size("http-get.client",    traffic.http_get.client_headers,    508, "~500 bytes max")
    if traffic.http_post is not None:
        _warn_header_size("http-post.client",   traffic.http_post.client_headers,   508, "~500 bytes max")
    if traffic.http_stager is not None:
        _warn_header_size("http-stager.client", traffic.http_stager.client_headers, 303, "~300 bytes max")
    # Warn when http-get/http-post URIs approach Cobalt Strike's 63-byte limit.
    if traffic.http_get is not None:
        _warn_uri_length("http-get.uri",  traffic.http_get.uri)
    if traffic.http_post is not None:
        _warn_uri_length("http-post.uri", traffic.http_post.uri)
    print(f"Profile written to {args.output}")


def _cmd_run(args: argparse.Namespace) -> None:
    from malleon.parser.http_extractor import extract
    from malleon.profile.builder import populate

    if not args.profile.exists():
        print(f"error: base profile not found: {args.profile}", file=sys.stderr)
        sys.exit(2)

    binary_cmd = [a for a in args.binary_cmd if a != "--"]
    if not binary_cmd:
        print("error: binary command is required", file=sys.stderr)
        sys.exit(2)

    binary_path = Path(binary_cmd[0])
    binary_args = binary_cmd[1:]

    runner = ProxyRunner(args.port)
    runner.start()
    try:
        exit_code = launch_binary(binary_path, args.port, binary_args, args.timeout)
    finally:
        runner.stop()

    flows = runner.flows
    _bc    = getattr(args, "body_camouflage",       False)
    _fbc   = getattr(args, "force_body_camouflage", False)
    _split = getattr(args, "body_split",            128)
    camouflage = _bc or _fbc
    traffic = extract(
        flows,
        target_domain=args.target_domain,
        body_camouflage=camouflage,
        body_split=_split,
    )
    populate(
        args.profile, traffic, args.output,
        body_camouflage=_bc,
        force_body_camouflage=_fbc,
    )
    # Warn when client header blocks approach Cobalt Strike's size limits.
    if traffic.http_get is not None:
        _warn_header_size("http-get.client",    traffic.http_get.client_headers,    508, "~500 bytes max")
    if traffic.http_post is not None:
        _warn_header_size("http-post.client",   traffic.http_post.client_headers,   508, "~500 bytes max")
    if traffic.http_stager is not None:
        _warn_header_size("http-stager.client", traffic.http_stager.client_headers, 303, "~300 bytes max")
    # Warn when http-get/http-post URIs approach Cobalt Strike's 63-byte limit.
    if traffic.http_get is not None:
        _warn_uri_length("http-get.uri",  traffic.http_get.uri)
    if traffic.http_post is not None:
        _warn_uri_length("http-post.uri", traffic.http_post.uri)

    populated: list[str] = []
    if traffic.useragent is not None:
        populated.append("useragent")
    if traffic.http_get is not None:
        populated.append("http-get")
    if traffic.http_post is not None:
        populated.append("http-post")
    if traffic.http_stager is not None:
        populated.append("http-stager")
    # http-config is populated whenever server headers are available
    server_headers = (
        traffic.http_get.server_headers if traffic.http_get is not None else []
    ) or (
        traffic.http_post.server_headers if traffic.http_post is not None else []
    )
    if server_headers:
        populated.append("http-config")

    fields_str = ", ".join(populated) if populated else "(none)"
    print(f"{len(flows)} flow(s) captured")
    print(f"Fields populated: {fields_str}")
    print(f"Profile written to {args.output}")

    if exit_code not in (0, -1):
        sys.exit(exit_code)


def _cmd_setup(args: argparse.Namespace) -> None:
    if sys.platform != "win32":
        print("malleon setup is Windows-only - no action required on this platform.")
        return
    from malleon.proxy.winsetup import (
        ensure_ca_cert, install_ca_cert, set_system_proxy, set_wininet_proxy,
    )
    pem = ensure_ca_cert()
    install_ca_cert(pem)
    set_system_proxy(args.port)
    set_wininet_proxy(args.port)
    print("Setup complete.")


_DUMP_SEP = "-" * 131


def _format_flow_dump(n: int, flow: dict) -> str:
    """Format a single captured flow as a Burp-style raw HTTP request/response dump."""
    from malleon.parser.http_extractor import _flow_host
    req = flow["request"]
    method = req["method"].upper()
    scheme = req.get("scheme", "https")
    host = _flow_host(flow)
    path = req["path"]
    req_ct = "-"
    for hname, hval in req["headers"]:
        if hname.lower() == "content-type":
            req_ct = hval.split(";", 1)[0].strip()
            break
    url = f"{scheme}://{host}{path}"
    title = f"ID {n} | {method} {url} ({req_ct})"
    http_ver = req.get("http_version", "HTTP/1.1")
    lines: list[str] = [_DUMP_SEP, title, _DUMP_SEP, f"{method} {path} {http_ver}"]
    for hname, hval in req["headers"]:
        lines.append(f"{hname}: {hval}")
    body_field = req.get("body")
    if body_field and isinstance(body_field, dict) and body_field.get("encoding") == "utf-8":
        data = body_field.get("data", "")
        if data:
            lines.append("")
            lines.append(data)
    lines.append("")
    resp = flow.get("response")
    if resp is not None:
        resp_ver = resp.get("http_version", "HTTP/1.1")
        status_code = resp.get("status_code", "")
        reason = resp.get("reason", "")
        lines.append(f"{resp_ver} {status_code} {reason}")
        for hname, hval in resp["headers"]:
            lines.append(f"{hname}: {hval}")
        resp_body = resp.get("body")
        if resp_body and isinstance(resp_body, dict) and resp_body.get("encoding") == "utf-8":
            data = resp_body.get("data", "")
            if data:
                lines.append("")
                if len(data) > 512:
                    lines.append(data[:512] + "[truncated]")
                else:
                    lines.append(data)
    return "\n".join(lines) + "\n"


def _cmd_inspect(args: argparse.Namespace) -> None:
    from collections import Counter
    from malleon.proxy.intermediate import read_intermediate
    from malleon.parser.http_extractor import _flow_host

    if not args.flows_json.exists():
        print(f"error: flows file not found: {args.flows_json}", file=sys.stderr)
        sys.exit(2)

    flows = read_intermediate(args.flows_json)

    if not flows:
        print("No flows found.")
        return

    if getattr(args, "show_id", None) is not None:
        raw = [x.strip() for x in args.show_id.split(",") if x.strip()]
        total = len(flows)
        seen: set[int] = set()
        ordered: list[int] = []
        for token in raw:
            n = int(token)
            if n in seen:
                continue
            seen.add(n)
            ordered.append(n)
        ordered.sort()
        for n in ordered:
            if n < 1 or n > total:
                print(
                    f"warning: flow index {n} is out of range (total flows: {total}) - skipped.",
                    file=sys.stderr,
                )
                continue
            print(_format_flow_dump(n, flows[n - 1]))
        return

    def _response_ct(flow: dict) -> str:
        resp = flow.get("response")
        if resp is None:
            return "-"
        for name, value in resp["headers"]:
            if name.lower() == "content-type":
                return value.split(";", 1)[0].strip()
        return "-"

    filter_method = getattr(args, "method", None)
    filter_domain = getattr(args, "domain", None)
    filtering = filter_method is not None or filter_domain is not None

    rows: list[tuple[str, ...]] = []
    for i, flow in enumerate(flows, 1):
        method = flow["request"]["method"].upper()
        host = _flow_host(flow)
        if filter_method is not None and method != filter_method.upper():
            continue
        if filter_domain is not None and host != filter_domain.lower():
            continue
        path = flow["request"]["path"]
        uri = path if len(path) <= 40 else path[:37] + "..."
        ct = _response_ct(flow)
        rows.append((str(i), method, host, uri, ct))

    col_headers = ("#", "Method", "Host", "URI", "Content-Type")
    widths = [
        max(len(col_headers[i]), max((len(row[i]) for row in rows), default=0))
        for i in range(len(col_headers))
    ]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    print(fmt.format(*col_headers))
    for row in rows:
        print(fmt.format(*row))

    if filtering:
        return

    print()

    domain_counts = Counter(_flow_host(f) for f in flows)
    sorted_domains = domain_counts.most_common()
    max_domain_len = max(len(d) for d, _ in sorted_domains) if sorted_domains else 0

    print("Domains:")
    for domain, count in sorted_domains:
        print(f"  {domain:<{max_domain_len}}  {count} flow(s)")


def _cmd_cleanup(args: argparse.Namespace) -> None:
    if sys.platform != "win32":
        print("malleon cleanup is Windows-only - no action required on this platform.")
        return
    from malleon.proxy.winsetup import reset_system_proxy, reset_wininet_proxy, uninstall_ca_cert
    reset_system_proxy()
    print("WinHTTP proxy reset to direct.", flush=True)
    reset_wininet_proxy()
    uninstall_ca_cert()
    print("Cleanup complete.")


def _cmd_capture(args: argparse.Namespace) -> None:
    binary_cmd = [a for a in args.binary_cmd if a != "--"]
    if not binary_cmd:
        print("error: binary command is required", file=sys.stderr)
        sys.exit(2)

    binary_path = Path(binary_cmd[0])
    binary_args = binary_cmd[1:]

    runner = ProxyRunner(args.port)
    runner.start()
    try:
        exit_code = launch_binary(binary_path, args.port, binary_args, args.timeout)
    finally:
        runner.stop()

    flows = runner.flows
    write_intermediate(flows, args.output)
    print(f"{len(flows)} flows -> {args.output}")

    if exit_code not in (0, -1):
        sys.exit(exit_code)
