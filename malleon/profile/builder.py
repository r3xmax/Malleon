from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

from malleon.parser.http_extractor import HttpBlock, ParsedTraffic, _filter_headers

# ---------------------------------------------------------------------------
# AST nodes
# ---------------------------------------------------------------------------

@dataclass
class Directive:
    keyword: str
    raw_args: list[str]  # token values verbatim: words unquoted, strings with their quotes

    def serialize(self, indent: str) -> str:
        parts = [self.keyword] + self.raw_args
        return f"{indent}{' '.join(parts)};\n"


@dataclass
class Block:
    name: str
    children: list[Directive | Block | Raw] = field(default_factory=list)

    def serialize(self, indent: str) -> str:
        inner = indent + "    "
        body = "".join(
            child.serialize(inner) if isinstance(child, (Directive, Block)) else child.text
            for child in self.children
        )
        return f"{indent}{self.name} {{\n{body}{indent}}}\n"


@dataclass
class Raw:
    text: str  # preserved verbatim, including original whitespace

    def serialize(self, _indent: str) -> str:
        return self.text


Profile = list[Directive | Block | Raw]

# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------

_TOKEN_RE = re.compile(
    r'(?P<comment>#[^\n]*\n?)'
    r'|(?P<string>"(?:[^"\\]|\\.)*")'
    r'|(?P<lbrace>\{)'
    r'|(?P<rbrace>\})'
    r'|(?P<semi>;)'
    r'|(?P<word>[A-Za-z0-9_\-]+)'
    r'|(?P<ws>[ \t\r\n]+)',
)


@dataclass
class _Tok:
    kind: str
    val: str
    start: int
    end: int


def _tokenize(text: str) -> list[_Tok]:
    return [
        _Tok(kind=m.lastgroup, val=m.group(), start=m.start(), end=m.end())
        for m in _TOKEN_RE.finditer(text)
        if m.lastgroup != "ws"
    ]


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

# Blocks immediately inside a promoted root block that are parsed as real Block nodes.
_HTTP_BLOCK_INNER_ALLOWLIST = frozenset({"client", "server"})


def _parse(text: str, blocks_to_promote: frozenset[str] = frozenset()) -> Profile:
    """Parse a profile text string into a list of AST nodes."""
    tokens = _tokenize(text)
    pos = [0]

    def peek(offset: int = 0) -> _Tok | None:
        i = pos[0] + offset
        return tokens[i] if i < len(tokens) else None

    def consume() -> _Tok:
        t = tokens[pos[0]]
        pos[0] += 1
        return t

    def consume_raw_block() -> Raw:
        """Consume a named-variant block from the token stream as a raw text slice."""
        start = tokens[pos[0]].start
        pos[0] += 3  # skip word, string, lbrace
        depth = 1
        end = start
        while pos[0] < len(tokens) and depth > 0:
            tok = tokens[pos[0]]
            pos[0] += 1
            end = tok.end
            if tok.kind == "lbrace":
                depth += 1
            elif tok.kind == "rbrace":
                depth -= 1
        raw = text[start:end]
        if not raw.endswith("\n"):
            raw += "\n"
        return Raw(raw)

    def consume_raw_unnamed_block(name_tok: _Tok) -> Raw:
        """Consume an unnamed block whose name token was already consumed as a raw text slice."""
        pos[0] += 1  # skip lbrace
        depth = 1
        end = name_tok.start
        while pos[0] < len(tokens) and depth > 0:
            tok = tokens[pos[0]]
            pos[0] += 1
            end = tok.end
            if tok.kind == "lbrace":
                depth += 1
            elif tok.kind == "rbrace":
                depth -= 1
        raw = text[name_tok.start:end]
        if not raw.endswith("\n"):
            raw += "\n"
        return Raw(raw)

    def parse_items(stop_at_rbrace: bool, context: str) -> list:
        """Parse child nodes inside a promoted block according to the given context."""
        items = []
        while pos[0] < len(tokens):
            tok = peek()
            if tok is None:
                break
            if tok.kind == "rbrace":
                if stop_at_rbrace:
                    break
                consume()
                items.append(Raw(tok.val + "\n"))
                continue
            if tok.kind == "comment":
                consume()
                # Recover horizontal whitespace that preceded # on the same line.
                # The tokenizer discards it as "ws"; we read it back from the source
                # so the Raw node is self-contained with its original indentation.
                i = tok.start - 1
                prefix: list[str] = []
                while i >= 0 and text[i] in (" ", "\t"):
                    prefix.append(text[i])
                    i -= 1
                indent = "".join(reversed(prefix))
                val = tok.val if tok.val.endswith("\n") else tok.val + "\n"
                items.append(Raw(indent + val))
                continue
            if tok.kind == "word":
                next1 = peek(1)
                next2 = peek(2)
                # Named variant: word string { -> Raw (preserved verbatim, all levels)
                if next1 and next1.kind == "string" and next2 and next2.kind == "lbrace":
                    items.append(consume_raw_block())
                    continue
                # Unnamed block: word {
                if next1 and next1.kind == "lbrace":
                    name_tok = consume()
                    name = name_tok.val
                    if context == "http_block" and name in _HTTP_BLOCK_INNER_ALLOWLIST:
                        consume()  # lbrace
                        children = parse_items(stop_at_rbrace=True, context="leaf")
                        if peek() and peek().kind == "rbrace":
                            consume()
                        items.append(Block(name=name, children=children))
                    else:
                        # All other unnamed blocks -> Raw verbatim
                        items.append(consume_raw_unnamed_block(name_tok))
                    continue
                # Directive: keyword [word|string]* ;
                keyword = consume().val
                raw_args = []
                while peek() and peek().kind in ("word", "string"):
                    raw_args.append(consume().val)
                if peek() and peek().kind == "semi":
                    consume()
                items.append(Directive(keyword=keyword, raw_args=raw_args))
                continue
            # Stray token
            items.append(Raw(consume().val))
        return items

    def parse_config_block(gap_start: int) -> list:
        """Parse the inside of an http-config block into Directive and Raw nodes."""
        items: list = []
        depth = 0  # brace depth; break on } only at depth 0

        while pos[0] < len(tokens):
            tok = peek()
            if tok is None:
                break
            if tok.kind == "rbrace":
                if depth == 0:
                    break  # closing } of http-config; leave unconsumed
                depth -= 1
                consume()
                continue
            if tok.kind == "lbrace":
                depth += 1
                consume()
                continue

            next1 = peek(1)

            is_set_headers = (
                depth == 0
                and tok.kind == "word"
                and tok.val == "set"
                and next1 is not None
                and next1.kind == "word"
                and next1.val == "headers"
            )
            is_header = (
                depth == 0
                and tok.kind == "word"
                and tok.val == "header"
                and next1 is not None
                and next1.kind == "string"
            )

            if is_set_headers or is_header:
                # Flush gap accumulated before this directive
                if tok.start > gap_start:
                    items.append(Raw(text[gap_start : tok.start]))
                # Parse as Directive
                keyword = consume().val
                raw_args = []
                while peek() and peek().kind in ("word", "string"):
                    raw_args.append(consume().val)
                semi_end = tokens[pos[0] - 1].end if pos[0] > 0 else len(text)
                if peek() and peek().kind == "semi":
                    semi_end = consume().end
                # Directive.serialize() emits its own '\n'; skip the matching
                # newline in the source so the next gap does not double it.
                gap_start = semi_end
                if gap_start < len(text) and text[gap_start] == "\r":
                    gap_start += 1
                if gap_start < len(text) and text[gap_start] == "\n":
                    gap_start += 1
                items.append(Directive(keyword=keyword, raw_args=raw_args))
            else:
                consume()  # part of current gap; advance past this token

        # Flush final gap up to (but not including) the closing }
        if pos[0] < len(tokens) and peek() is not None and peek().kind == "rbrace":
            closing_pos = peek().start
            if closing_pos > gap_start:
                items.append(Raw(text[gap_start : closing_pos]))
        elif gap_start < len(text):
            items.append(Raw(text[gap_start:]))

        return items

    def parse_root() -> Profile:
        """Parse the root profile level into alternating Raw gap segments and promoted Block nodes."""
        items: list = []
        gap_start = 0  # byte offset in text where the current gap segment begins
        depth = 0      # brace depth; match promoted blocks only at depth 0

        while pos[0] < len(tokens):
            tok = peek()
            next1 = peek(1)
            if tok is None:
                break
            if tok.kind == "lbrace":
                depth += 1
                consume()
            elif tok.kind == "rbrace":
                depth -= 1
                consume()
            elif (
                depth == 0
                and tok.kind == "word"
                and tok.val in blocks_to_promote
                and next1 is not None
                and next1.kind == "lbrace"  # named variants (word string {) excluded
            ):
                # Flush gap text accumulated before this block
                if tok.start > gap_start:
                    items.append(Raw(text[gap_start : tok.start]))
                # Parse the promoted block as a real Block node
                name = consume().val     # word
                lbrace_tok = consume()   # lbrace
                if name == "http-config":
                    # Block.serialize() emits '{\n'; skip the matching newline so
                    # the first gap segment does not start with a duplicate '\n'.
                    config_gap_start = lbrace_tok.end
                    if config_gap_start < len(text) and text[config_gap_start] == "\r":
                        config_gap_start += 1
                    if config_gap_start < len(text) and text[config_gap_start] == "\n":
                        config_gap_start += 1
                    children = parse_config_block(config_gap_start)
                else:
                    children = parse_items(stop_at_rbrace=True, context="http_block")
                if peek() and peek().kind == "rbrace":
                    end_tok = consume()
                    gap_start = end_tok.end  # gap resumes immediately after }
                    # Block.serialize() appends its own '\n' after '}'; skip the
                    # matching newline in the source so the gap does not double it.
                    if gap_start < len(text) and text[gap_start] == "\r":
                        gap_start += 1  # handle \r\n line endings
                    if gap_start < len(text) and text[gap_start] == "\n":
                        gap_start += 1
                else:
                    gap_start = tokens[pos[0] - 1].end if pos[0] > 0 else len(text)
                items.append(Block(name=name, children=children))
            else:
                consume()  # token belongs to the current gap; advance past it

        # Flush trailing gap (or entire file when blocks_to_promote is empty)
        if gap_start < len(text):
            items.append(Raw(text[gap_start:]))

        return items

    return parse_root()


# ---------------------------------------------------------------------------
# Serializer
# ---------------------------------------------------------------------------

def _serialize(profile: Profile) -> str:
    return "".join(
        node.serialize("") if isinstance(node, (Directive, Block)) else node.text
        for node in profile
    )


# ---------------------------------------------------------------------------
# Builder helpers
# ---------------------------------------------------------------------------

def _upsert_set(children: list, option: str, value: str) -> None:
    for i, child in enumerate(children):
        if (
            isinstance(child, Directive)
            and child.keyword == "set"
            and child.raw_args
            and child.raw_args[0] == option
        ):
            children[i] = Directive(keyword="set", raw_args=[option, f'"{value}"'])
            return
    children.append(Directive(keyword="set", raw_args=[option, f'"{value}"']))


def _upsert_kv(children: list, keyword: str, name: str, value: str) -> None:
    """Insert or update a two-argument keyword directive matched by name."""
    for i, child in enumerate(children):
        if (
            isinstance(child, Directive)
            and child.keyword == keyword
            and child.raw_args
            and child.raw_args[0].strip('"').lower() == name.lower()
        ):
            children[i] = Directive(keyword=keyword, raw_args=[f'"{name}"', f'"{value}"'])
            return
    children.append(Directive(keyword=keyword, raw_args=[f'"{name}"', f'"{value}"']))


def _find_or_create_block(children: list, name: str) -> Block:
    for child in children:
        if isinstance(child, Block) and child.name == name:
            return child
    block = Block(name=name)
    children.append(block)
    return block


# ---------------------------------------------------------------------------
# Body-camouflage helpers
# ---------------------------------------------------------------------------

# Matches an `output { ... }` block as it appears at the start of a Raw node's text.
# A Raw node for `output {}` starts with the keyword (no leading whitespace, since
# the tokenizer slices from name_tok.start).
_OUTPUT_BLOCK_RE = re.compile(r"^output\s*\{")


def _has_output_raw(children: list) -> bool:
    """Check whether any Raw node in the children list is an output block."""
    return any(
        isinstance(c, Raw) and _OUTPUT_BLOCK_RE.match(c.text.lstrip())
        for c in children
    )


def _remove_output_raws(children: list) -> None:
    """Remove all Raw output block nodes from the children list."""
    indices = [
        i for i, c in enumerate(children)
        if isinstance(c, Raw) and _OUTPUT_BLOCK_RE.match(c.text.lstrip())
    ]
    for i in reversed(indices):
        children.pop(i)


def _move_metadata_to_end(children: list) -> None:
    """Move metadata and id Raw nodes to the end of the children list."""
    def _is_metadata_or_id(node) -> bool:
        if not isinstance(node, Raw):
            return False
        text = node.text.lstrip()
        return text.startswith("metadata") or text.startswith("id")

    rest = [n for n in children if not _is_metadata_or_id(n)]
    meta = [n for n in children if _is_metadata_or_id(n)]
    children[:] = rest + meta


def _inject_output_block(
    children: list,
    prepend: str,
    append: str,
    include_encoding: bool = True,
) -> None:
    """Append an output block directive to the children list."""
    inner: list = []
    if include_encoding:
        inner.append(Directive(keyword="base64", raw_args=[]))
    inner.append(Directive(keyword="prepend", raw_args=[f'"{prepend}"']))
    inner.append(Directive(keyword="append",  raw_args=[f'"{append}"']))
    inner.append(Directive(keyword="print",   raw_args=[]))
    output_block = Block(name="output", children=inner)
    children.append(output_block)


def _apply_body_camouflage(
    profile: list,
    block_name: str,
    prepend: str,
    append: str,
    force: bool,
    include_encoding: bool = True,
) -> None:
    """Inject or replace an output block in the named block's server section."""
    http_block = _find_or_create_block(profile, block_name)
    server = _find_or_create_block(http_block.children, "server")

    if _has_output_raw(server.children):
        if force:
            _remove_output_raws(server.children)
            _inject_output_block(server.children, prepend, append, include_encoding)
        else:
            print(
                f"warning: {block_name}.server already contains an 'output' block: "
                "skipping --body-camouflage (use --force-body-camouflage to replace it).",
                file=sys.stderr,
            )
    else:
        _inject_output_block(server.children, prepend, append, include_encoding)


# ---------------------------------------------------------------------------
# Core builder
# ---------------------------------------------------------------------------

def _apply_http_config(profile: Profile, server_headers: list[tuple[str, str]]) -> None:
    """Upsert set headers and header directives inside the http-config block."""
    config_block = _find_or_create_block(profile, "http-config")
    header_names = ", ".join(name for name, _ in server_headers)
    _upsert_set(config_block.children, "headers", header_names)
    for h_name, h_value in server_headers:
        _upsert_kv(config_block.children, "header", h_name, h_value)


def _apply_http_stager(
    profile: Profile,
    data: HttpBlock,
    uri_x86: str | None = None,
    uri_x64: str | None = None,
) -> None:
    """Upsert stager URIs, client headers, and server headers in the http-stager block."""
    stager_block = _find_or_create_block(profile, "http-stager")
    _upsert_set(stager_block.children, "uri_x86", uri_x86 if uri_x86 is not None else data.uri)
    _upsert_set(stager_block.children, "uri_x64", uri_x64 if uri_x64 is not None else data.uri)

    client = _find_or_create_block(stager_block.children, "client")
    for h_name, h_value in data.client_headers:
        _upsert_kv(client.children, "header", h_name, h_value)
    _move_metadata_to_end(client.children)

    server = _find_or_create_block(stager_block.children, "server")
    for h_name, h_value in data.server_headers:
        _upsert_kv(server.children, "header", h_name, h_value)


def _apply_http_block(profile: Profile, block_name: str, data: HttpBlock) -> None:
    http_block = _find_or_create_block(profile, block_name)
    _upsert_set(http_block.children, "uri", data.uri)

    client = _find_or_create_block(http_block.children, "client")
    for h_name, h_value in data.client_headers:
        _upsert_kv(client.children, "header", h_name, h_value)
    for p_name, p_value in data.query_params:
        _upsert_kv(client.children, "parameter", p_name, p_value)
    _move_metadata_to_end(client.children)

    server = _find_or_create_block(http_block.children, "server")
    for h_name, h_value in data.server_headers:
        _upsert_kv(server.children, "header", h_name, h_value)


def _splice_useragent(text: str, value: str) -> str:
    """Replace or append the set useragent directive in a profile text string."""
    tokens = _tokenize(text)
    depth = 0
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok.kind == "lbrace":
            depth += 1
        elif tok.kind == "rbrace":
            depth -= 1
        elif (
            depth == 0
            and tok.kind == "word"
            and tok.val == "set"
            and i + 1 < len(tokens)
            and tokens[i + 1].kind == "word"
            and tokens[i + 1].val == "useragent"
        ):
            # Scan forward to the terminating semicolon
            j = i + 2
            while j < len(tokens) and tokens[j].kind not in ("semi", "lbrace", "rbrace"):
                j += 1
            if j < len(tokens) and tokens[j].kind == "semi":
                new_directive = f'set useragent "{value}";'
                return text[: tok.start] + new_directive + text[tokens[j].end :]
            # Malformed (no semi before next brace) -- fall through to append
            break
        i += 1
    # Directive not found: append to end
    suffix = "" if text.endswith("\n") else "\n"
    return text + suffix + f'set useragent "{value}";\n'


def populate(
    base_profile_path: Path,
    traffic: ParsedTraffic,
    output_path: Path,
    body_camouflage: bool = False,
    force_body_camouflage: bool = False,
) -> None:
    """Read the base profile, populate it with extracted traffic fields, and write the result."""
    text = base_profile_path.read_text(encoding="utf-8")

    if traffic.useragent is not None:
        text = _splice_useragent(text, traffic.useragent)

    # Determine server_headers for http-config: prefer http_get, fall back to http_post.
    server_headers_for_config: list[tuple[str, str]] = (
        traffic.http_get.server_headers
        if traffic.http_get is not None and traffic.http_get.server_headers
        else traffic.http_post.server_headers
        if traffic.http_post is not None and traffic.http_post.server_headers
        else []
    )

    blocks_to_promote: set[str] = set()
    if traffic.http_get is not None:
        blocks_to_promote.add("http-get")
    if traffic.http_post is not None:
        blocks_to_promote.add("http-post")
    if server_headers_for_config:
        blocks_to_promote.add("http-config")
    if traffic.http_stager is not None:
        blocks_to_promote.add("http-stager")

    profile = _parse(text, frozenset(blocks_to_promote))

    if traffic.http_get is not None:
        _apply_http_block(profile, "http-get", traffic.http_get)

    if traffic.http_post is not None:
        _apply_http_block(profile, "http-post", traffic.http_post)

    if server_headers_for_config:
        # Strip headers that Cobalt Strike prohibits in http-config (e.g. content-type).
        # apply_escape=False: values in server_headers_for_config come from HttpBlock
        # which already had _escape_header_value applied at extraction time; re-escaping
        # would produce \\" (double-escaped) instead of \" in the written profile.
        server_headers_for_config = _filter_headers(
            server_headers_for_config, set(), context="http-config", apply_escape=False
        )
    if server_headers_for_config:
        _apply_http_config(profile, server_headers_for_config)

    if traffic.http_stager is not None:
        _apply_http_stager(
            profile,
            traffic.http_stager,
            uri_x86=traffic.stager_uri_x86,
            uri_x64=traffic.stager_uri_x64,
        )

    # Body-camouflage: inject output blocks into http-get.server and http-post.server.
    # http-stager.server.output does NOT accept base64 encoding (include_encoding=False).
    _camouflage_active = body_camouflage or force_body_camouflage
    if (
        _camouflage_active
        and traffic.server_body_prepend is not None
        and traffic.server_body_append is not None
    ):
        for blk_name, blk_data, enc in (
            ("http-get",    traffic.http_get,    True),
            ("http-post",   traffic.http_post,   True),
            ("http-stager", traffic.http_stager,  False),
        ):
            if blk_data is not None:
                _apply_body_camouflage(
                    profile, blk_name,
                    traffic.server_body_prepend,
                    traffic.server_body_append,
                    force=force_body_camouflage,
                    include_encoding=enc,
                )

    output_path.write_text(_serialize(profile), encoding="utf-8")
