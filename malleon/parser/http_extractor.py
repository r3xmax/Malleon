import sys
from dataclasses import dataclass, field, replace
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from malleon.proxy.intermediate import read_intermediate

_CLIENT_HEADER_BLOCKLIST = {"host", "user-agent"}
_SERVER_HEADER_BLOCKLIST = {"transfer-encoding", "content-length"}

# Headers that must never appear in a profile regardless of captured traffic.
# These are set dynamically at runtime and would break beacon reliability if
# baked in as static values.
DYNAMIC_HEADER_BLOCKLIST: frozenset[str] = frozenset({
    "date",
})

# Headers prohibited specifically inside http-config by Cobalt Strike.
# These are valid in http-get/http-post/http-stager server blocks but must
# never appear in http-config where CS sets them itself at runtime.
HTTP_CONFIG_EXTRA_BLOCKLIST: frozenset[str] = frozenset({
    "content-type",
})


@dataclass
class HttpBlock:
    uri: str
    client_headers: list[tuple[str, str]]
    query_params: list[tuple[str, str]]
    server_headers: list[tuple[str, str]]


@dataclass
class ParsedTraffic:
    useragent: str | None
    http_get: HttpBlock | None
    http_post: HttpBlock | None
    http_stager: HttpBlock | None = None
    # Body-camouflage fragments - populated only when --body-camouflage is active.
    # Holds cleaned prepend/append literals (quotes escaped, newlines removed).
    server_body_prepend: str | None = None
    server_body_append: str | None = None
    # Unique per-architecture stager URIs (base + "/x86" / "/x64").
    # Populated by extract(); None when http_stager is None.
    stager_uri_x86: str | None = None
    stager_uri_x64: str | None = None


# Content-Type prefixes/values that indicate text or structured data.
# Anything that does NOT match is considered binary (stager candidate).
_TEXT_CT_PREFIXES = ("text/",)
_STRUCTURED_CT_VALUES = frozenset({
    "application/json",
    "application/javascript",
    "application/xml",
    "application/xhtml+xml",
})


def _flow_host(flow: dict) -> str:
    """Extract the lowercased, port-stripped hostname from a captured flow."""
    req = flow["request"]
    # Direct host field written by mitmproxy into the intermediate JSON
    direct = req.get("host")
    if direct:
        return str(direct).split(":")[0].lower()
    # HTTP/1.1 Host header
    for name, value in req["headers"]:
        if name.lower() == "host":
            return value.split(":")[0].lower()
    # HTTP/2 :authority pseudo-header
    for name, value in req["headers"]:
        if name.lower() == ":authority":
            return value.split(":")[0].lower()
    return ""


def _filter_by_domain(flows: list[dict], domain: str) -> list[dict]:
    """Return only the flows whose host matches the given domain."""
    target = domain.lower()
    return [f for f in flows if _flow_host(f) == target]


def _filter_by_ids(flows: list[dict], ids: list[int]) -> list[dict]:
    """Filter flows to the given 1-based indices, preserving capture order."""
    total = len(flows)
    seen: set[int] = set()
    valid_zero: list[int] = []
    for n in ids:
        if n in seen:
            continue
        seen.add(n)
        zero = n - 1
        if zero < 0 or zero >= total:
            print(
                f"warning: flow index {n} is out of range (total flows: {total}) - skipped.",
                file=sys.stderr,
            )
        else:
            valid_zero.append(zero)
    # Sort so flows are always returned in original capture order regardless of the order the caller specified in --id/-i.
    valid_zero.sort()
    result = [flows[i] for i in valid_zero]
    if not result:
        raise ValueError("error: no valid flows after applying --id/-i filter.")
    return result


def extract(
    flows: list[dict],
    target_domain: str | None = None,
    body_camouflage: bool = False,
    body_split: int = 128,
) -> ParsedTraffic:
    """Extract traffic fields from a list of captured flows."""
    if target_domain is not None:
        filtered = _filter_by_domain(flows, target_domain)
        if filtered:
            flows = filtered
        else:
            print(
                f"warning: no flows matched --target-domain {target_domain!r}"
                " - using all flows.",
                file=sys.stderr,
            )

    http_get = _first_block(flows, "GET")
    http_post = _first_block(flows, "POST")
    # Prefer a dedicated stager endpoint whose URI differs from http-get's URI.
    # When the only binary GET has the same URI as http-get, exclude_uri causes
    # _first_stager_block to return None; the stager-fallback block below then
    # reuses http-get/http-post.
    http_stager = _first_stager_block(
        flows,
        exclude_uri=http_get.uri if http_get is not None else None,
    )

    # GET/POST mutual fallback: copies are made so the builder can modify each independently
    if http_get is None and http_post is not None:
        http_get = replace(
            http_post,
            client_headers=[
                (name, value) for name, value in http_post.client_headers
                if name.lower() not in {"content-type", "content-length"}
            ],
            query_params=list(http_post.query_params),
            server_headers=list(http_post.server_headers),
        )
        print(
            "warning: no GET flows captured: http-get populated from POST flow.\n"
            "         URI and headers may not be appropriate for a GET request.\n"
            "         Review http-get client headers before deploying.",
            file=sys.stderr,
        )
    elif http_post is None and http_get is not None:
        _ch = list(http_get.client_headers)
        if not any(name.lower() == "content-type" for name, _ in _ch):
            _ch.append(("Content-Type", "application/octet-stream"))
        http_post = replace(
            http_get,
            client_headers=_ch,
            query_params=list(http_get.query_params),
            server_headers=list(http_get.server_headers),
        )
        print(
            "warning: no POST flows captured: http-post populated from GET flow.\n"
            "         Content-Type set to application/octet-stream as fallback.\n"
            "         Review http-post client headers before deploying.",
            file=sys.stderr,
        )

    # Stager fallback: look for a binary Content-Type in already-selected blocks
    if http_stager is None:
        for block in (http_get, http_post):
            if block is not None and _block_has_binary_content_type(block):
                http_stager = replace(
                    block,
                    client_headers=list(block.client_headers),
                    query_params=list(block.query_params),
                    server_headers=list(block.server_headers),
                )
                print(
                    "warning: no binary GET flows captured: http-stager populated from\n"
                    "         existing flow as fallback. Review uri_x86/uri_x64 and\n"
                    "         client headers before deploying.",
                    file=sys.stderr,
                )
                break

    server_body_prepend = None
    server_body_append = None
    if body_camouflage:
        server_body_prepend, server_body_append = _extract_body_fragments(flows, body_split)

    # stager_uri_x86 and stager_uri_x64 always carry distinct URIs so that the
    # Cobalt Strike team server can tell apart x86 and x64 stage requests.
    stager_uri_x86: str | None = None
    stager_uri_x64: str | None = None
    if http_stager is not None:
        base = http_stager.uri
        stager_uri_x86 = base + "/x86"
        stager_uri_x64 = base + "/x64"

    return ParsedTraffic(
        useragent=_first_useragent(flows),
        http_get=http_get,
        http_post=http_post,
        http_stager=http_stager,
        server_body_prepend=server_body_prepend,
        server_body_append=server_body_append,
        stager_uri_x86=stager_uri_x86,
        stager_uri_x64=stager_uri_x64,
    )


def extract_from_file(
    path: Path,
    target_domain: str | None = None,
    body_camouflage: bool = False,
    body_split: int = 128,
    ids: list[int] | None = None,
) -> ParsedTraffic:
    flows = read_intermediate(path)
    if ids is not None:
        flows = _filter_by_ids(flows, ids)
    return extract(
        flows,
        target_domain=target_domain,
        body_camouflage=body_camouflage,
        body_split=body_split,
    )


def _first_useragent(flows: list[dict]) -> str | None:
    for flow in flows:
        for name, value in flow["request"]["headers"]:
            if name.lower() == "user-agent":
                return value
    return None


def _first_block(flows: list[dict], method: str) -> HttpBlock | None:
    for flow in flows:
        if flow["request"]["method"].upper() != method:
            continue
        if flow["response"] is None:
            continue
        return _build_block(flow)
    return None


def _build_block(flow: dict) -> HttpBlock:
    req = flow["request"]
    resp = flow["response"]
    full_path = req["path"]
    parsed = urlsplit(full_path)

    return HttpBlock(
        uri=parsed.path or "/",
        client_headers=_filter_headers(req["headers"], _CLIENT_HEADER_BLOCKLIST),
        query_params=parse_qsl(parsed.query),
        server_headers=_filter_headers(resp["headers"], _SERVER_HEADER_BLOCKLIST),
    )


def _first_stager_block(
    flows: list[dict],
    exclude_uri: str | None = None,
) -> HttpBlock | None:
    """Return the first GET flow whose response indicates binary content, skipping the excluded URI."""
    for flow in flows:
        if flow["request"]["method"].upper() != "GET":
            continue
        if flow["response"] is None:
            continue
        ct = _response_content_type(flow)
        if not _is_binary_content_type(ct):
            continue
        block = _build_block(flow)
        if exclude_uri is not None and block.uri == exclude_uri:
            continue
        return block
    return None


def _response_content_type(flow: dict) -> str:
    """Return the lowercased, parameter-stripped Content-Type of a flow's response."""
    for name, value in flow["response"]["headers"]:
        if name.lower() == "content-type":
            return value.split(";", 1)[0].strip().lower()
    return ""


def _is_binary_content_type(ct: str) -> bool:
    """Check whether a Content-Type value indicates binary content."""
    if not ct:
        return True   # absent Content-Type -> assume binary
    if ct.startswith(_TEXT_CT_PREFIXES):
        return False
    if ct in _STRUCTURED_CT_VALUES:
        return False
    return True


def _block_has_binary_content_type(block: HttpBlock) -> bool:
    """Check whether the block's server headers contain an explicit binary Content-Type."""
    for name, value in block.server_headers:
        if name.lower() == "content-type":
            ct = value.split(";", 1)[0].strip().lower()
            return _is_binary_content_type(ct)
    return False


def _escape_header_value(value: str) -> str:
    """Escape double-quote characters in a header value for Malleable C2 string literals."""
    return value.replace('"', '\\"')


def _filter_headers(
    headers: list[tuple[str, str]],
    blocklist: set[str],
    context: str = "",
    apply_escape: bool = True,
) -> list[tuple[str, str]]:
    """Remove blocked headers and apply context-specific exclusions."""
    result = []
    for name, value in headers:
        lower = name.lower()
        if lower in DYNAMIC_HEADER_BLOCKLIST:
            continue
        if context == "http-config" and lower in HTTP_CONFIG_EXTRA_BLOCKLIST:
            continue
        if lower in blocklist:
            continue
        result.append((name, _escape_header_value(value) if apply_escape else value))
    return result


# ---------------------------------------------------------------------------
# Body-camouflage helpers
# ---------------------------------------------------------------------------

def _clean_body_fragment(text: str) -> str:
    """Sanitize a body fragment for safe inclusion in a Malleable C2 string literal."""
    text = text.replace('"', '\\"')
    text = text.replace('\r\n', ' ').replace('\r', ' ').replace('\n', ' ')
    return text


def _extract_body_fragments(
    flows: list[dict],
    body_split: int,
) -> tuple[str | None, str | None]:
    """Return prepend and append body fragments from the first suitable text response."""
    for flow in flows:
        resp = flow.get("response")
        if resp is None:
            continue
        ct = _response_content_type(flow)
        if _is_binary_content_type(ct):
            continue
        body_field = resp.get("body")
        if not body_field:
            continue
        if not isinstance(body_field, dict):
            continue
        if body_field.get("encoding") != "utf-8":
            continue  # base64 -> binary
        data: str = body_field.get("data", "")
        if not data:
            continue

        if len(data) < 2 * body_split:
            print(
                f"warning: response body ({len(data)} chars) is shorter than "
                f"2x --body-split ({2 * body_split}): "
                "--body-camouflage split may be ineffective.",
                file=sys.stderr,
            )

        prepend = _clean_body_fragment(data[:body_split])
        append = _clean_body_fragment(data[-body_split:] if len(data) >= body_split else data)
        return prepend, append

    return None, None
