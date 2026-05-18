#!/usr/bin/env python3
"""Generate code-on-white SVG snippets.

- No title/heading bar.
- Comments stripped from source.
- All SVGs rendered at the same width.
"""
from __future__ import annotations

import html
import re
from pathlib import Path

OUT = Path(__file__).parent
SVG_DIR = OUT / "svg"
SVG_DIR.mkdir(exist_ok=True)

FONT_FAMILY = "'JetBrains Mono','Fira Code',Menlo,Consolas,monospace"
FONT_SIZE = 14
CHAR_W = 8.42      # measured for 14px JetBrains/Menlo-ish monospace
LINE_H = 21
PAD_X = 24
PAD_Y = 20

PY_KEYWORDS = {
    "def", "class", "return", "if", "elif", "else", "for", "while", "import",
    "from", "as", "in", "is", "not", "and", "or", "None", "True", "False",
    "self", "super", "pass", "lambda", "with",
}
PY_TYPES = {"int", "float", "str", "bool", "bytes", "list", "dict", "tuple", "set", "Any"}

GO_KEYWORDS = {
    "package", "import", "type", "struct", "func", "return", "if", "else",
    "for", "range", "var", "const", "map", "chan", "interface", "nil",
    "true", "false",
}
GO_TYPES = {
    "byte", "int", "int32", "uint32", "uint8", "int64", "uint64",
    "string", "error", "float64", "float32", "bool",
}

YAML_KEY_RE = re.compile(r"^(\s*)([A-Za-z_][\w-]*)(:)(.*)$")
YAML_STR_RE = re.compile(r"(\"[^\"]*\")")

GO_STR_RE = re.compile(r"(\"[^\"]*\"|`[^`]*`)")
GO_TOKEN_RE = re.compile(r"\b([A-Za-z_]\w*)\b")
GO_NUM_RE = re.compile(r"\b(\d+)\b")


def strip_go_comments(code: str) -> str:
    out: list[str] = []
    for line in code.splitlines():
        s = line.split("//", 1)[0].rstrip()
        if s.strip() == "" and (not out or out[-1].strip() == ""):
            continue
        out.append(s)
    while out and out[-1].strip() == "":
        out.pop()
    return "\n".join(out)


def strip_yaml_comments(code: str) -> str:
    out: list[str] = []
    for line in code.splitlines():
        if line.lstrip().startswith("#"):
            continue
        # strip trailing #-comment, but only when not inside quotes
        in_s = False
        cut = -1
        for i, ch in enumerate(line):
            if ch == '"':
                in_s = not in_s
            elif ch == "#" and not in_s:
                cut = i
                break
        s = (line[:cut] if cut >= 0 else line).rstrip()
        if s.strip() == "" and (not out or out[-1].strip() == ""):
            continue
        out.append(s)
    while out and out[-1].strip() == "":
        out.pop()
    return "\n".join(out)


def hi_go_line(line: str) -> str:
    """Return SVG-safe spans for a Go line (string + keyword + number)."""
    # Tokenize by strings first.
    parts: list[tuple[str, str]] = []  # (kind, text)
    idx = 0
    for m in GO_STR_RE.finditer(line):
        if m.start() > idx:
            parts.append(("code", line[idx:m.start()]))
        parts.append(("str", m.group(0)))
        idx = m.end()
    if idx < len(line):
        parts.append(("code", line[idx:]))

    out: list[str] = []
    for kind, text in parts:
        if kind == "str":
            out.append(f'<tspan fill="#0a3069">{html.escape(text)}</tspan>')
            continue
        # split into tokens & non-token chunks
        last = 0
        for m in GO_TOKEN_RE.finditer(text):
            if m.start() > last:
                out.append(html.escape(text[last:m.start()]))
            tok = m.group(0)
            if tok in GO_KEYWORDS:
                out.append(f'<tspan fill="#cf222e">{tok}</tspan>')
            elif tok in GO_TYPES:
                out.append(f'<tspan fill="#0550ae">{tok}</tspan>')
            else:
                out.append(html.escape(tok))
            last = m.end()
        if last < len(text):
            tail = text[last:]
            # highlight numbers in the tail
            tail = GO_NUM_RE.sub(r'<tspan fill="#0550ae">\1</tspan>', html.escape(tail))
            out.append(tail)
    return "".join(out)


PY_STR_RE = re.compile(r'(\"\"\".*?\"\"\"|\'\'\'.*?\'\'\'|\"[^\"]*\"|\'[^\']*\')')
PY_TOKEN_RE = re.compile(r"\b([A-Za-z_]\w*)\b")
PY_NUM_RE = re.compile(r"\b(\d+)\b")


def strip_py_comments(code: str) -> str:
    out: list[str] = []
    for line in code.splitlines():
        s = re.sub(r"\s+#.*$", "", line).rstrip()
        if re.match(r"^\s*#", s):
            continue
        # drop single-line docstrings ("""...""")
        if re.match(r'^\s*("""[^"]*"""|\'\'\'[^\']*\'\'\')\s*$', s):
            continue
        if s.strip() == "" and (not out or out[-1].strip() == ""):
            continue
        out.append(s)
    while out and out[-1].strip() == "":
        out.pop()
    return "\n".join(out)


def hi_py_line(line: str) -> str:
    parts: list[tuple[str, str]] = []
    idx = 0
    for m in PY_STR_RE.finditer(line):
        if m.start() > idx:
            parts.append(("code", line[idx:m.start()]))
        parts.append(("str", m.group(0)))
        idx = m.end()
    if idx < len(line):
        parts.append(("code", line[idx:]))

    out: list[str] = []
    for kind, text in parts:
        if kind == "str":
            out.append(f'<tspan fill="#0a3069">{html.escape(text)}</tspan>')
            continue
        last = 0
        for m in PY_TOKEN_RE.finditer(text):
            if m.start() > last:
                out.append(html.escape(text[last:m.start()]))
            tok = m.group(0)
            if tok in PY_KEYWORDS:
                out.append(f'<tspan fill="#cf222e">{tok}</tspan>')
            elif tok in PY_TYPES:
                out.append(f'<tspan fill="#0550ae">{tok}</tspan>')
            else:
                out.append(html.escape(tok))
            last = m.end()
        if last < len(text):
            tail = PY_NUM_RE.sub(r'<tspan fill="#0550ae">\1</tspan>', html.escape(text[last:]))
            out.append(tail)
    return "".join(out)


def hi_yaml_line(line: str) -> str:
    m = YAML_KEY_RE.match(line)
    if m:
        indent, key, colon, rest = m.groups()
        rest_h = YAML_STR_RE.sub(r'<tspan fill="#0a3069">\1</tspan>', html.escape(rest))
        return (
            html.escape(indent)
            + f'<tspan fill="#0550ae">{html.escape(key)}</tspan>'
            + html.escape(colon)
            + rest_h
        )
    return YAML_STR_RE.sub(r'<tspan fill="#0a3069">\1</tspan>', html.escape(line))


def hi_plain_line(line: str) -> str:
    return html.escape(line)


def make_svg(lines: list[str], hi_fn, width_px: int) -> str:
    n = len(lines)
    height = PAD_Y * 2 + n * LINE_H
    body_parts: list[str] = []
    y = PAD_Y + FONT_SIZE
    for line in lines:
        body_parts.append(
            f'<text x="{PAD_X}" y="{y:.0f}" xml:space="preserve">{hi_fn(line)}</text>'
        )
        y += LINE_H
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width_px}" height="{height}" '
        f'viewBox="0 0 {width_px} {height}">'
        f'<rect width="100%" height="100%" fill="#ffffff"/>'
        f'<g font-family="{FONT_FAMILY}" font-size="{FONT_SIZE}" fill="#111">'
        + "".join(body_parts)
        + "</g></svg>\n"
    )


# ---- content -------------------------------------------------------------

PHASES: list[tuple[str, str]] = [
    ("01_session_open", """type SessionOpen struct{}

type VerificationSession struct {
    SessionID SessionID
}

type Manifest struct {
    CKKS                 json.RawMessage `json:"ckks"`
    LLKNBase             int             `json:"llkn_base"`
    LLKNLogPHK           []int           `json:"llkn_log_phk"`
    AuthenticatorLambda  int             `json:"authenticator_lambda"`
    AuthenticatorEpsilon float64         `json:"authenticator_epsilon"`
    FloodSigma           float64         `json:"flood_sigma"`
    ExtraRotationIndices []int           `json:"extra_rotation_indices,omitempty"`
    InputLevel           int             `json:"input_level"`
}"""),
    ("02_keygen", """type VClientPKShare struct {
    ShareEval multiparty.PublicKeyGenShare
    ShareTop  multiparty.PublicKeyGenShare
}

type VAgentPKShare struct {
    ShareEval multiparty.PublicKeyGenShare
    ShareTop  multiparty.PublicKeyGenShare
}

type VClientRLKRound1 struct {
    Share multiparty.RelinearizationKeyGenShare
}

type VAgentRLKRound1 struct {
    Share multiparty.RelinearizationKeyGenShare
}

type VClientRLKRound2 struct {
    Share multiparty.RelinearizationKeyGenShare
}

type VClientGaloisShares struct {
    MasterShares []multiparty.GaloisKeyGenShare
}

type InferEvalKeys struct {
    RLK       *rlwe.RelinearizationKey
    PKTop     *rlwe.PublicKey
    GKSMaster map[int]*hierkeys.MasterKey
}"""),
    ("03_encrypt_infer", """type EncryptedImage struct {
    Ct *rlwe.Ciphertext
}

type InferenceResult struct {
    Ct *rlwe.Ciphertext
}"""),
    ("04_decrypt", """type AuthenticatedResult struct {
    Ct *rlwe.Ciphertext
}

type PartialDecryption struct {
    Share multiparty.KeySwitchShare
}

type VerdictNotification struct {
    Verdict Verdict
}"""),
]


def main() -> None:
    snippets: list[tuple[str, list[str], object]] = []

    for slug, code in PHASES:
        cleaned = strip_go_comments(code)
        snippets.append((slug, cleaned.splitlines(), hi_go_line))

    cli_help = Path("/tmp/ppiav-cli-help.txt").read_text().rstrip("\n")
    snippets.append(("05_ppiav-cli_help", cli_help.splitlines(), hi_plain_line))

    compose = Path("/home/butvinm/Dev/ppiav/deploy/docker-compose.orion.yaml").read_text()
    compose = strip_yaml_comments(compose)
    snippets.append(("06_docker-compose.orion", compose.splitlines(), hi_yaml_line))

    c3ae = Path("/home/butvinm/Dev/ppiav/models/models/c3ae_fhe.py").read_text()
    c3ae = strip_py_comments(c3ae)
    c3ae_lines = [
        l for l in c3ae.splitlines()
        if not re.match(r"^\s*(from|import)\s", l)
    ]
    while c3ae_lines and c3ae_lines[0].strip() == "":
        c3ae_lines.pop(0)
    snippets.append(("07_c3ae_fhe", c3ae_lines, hi_py_line))

    max_cols = max(max((len(l) for l in lines), default=0) for _, lines, _ in snippets)
    width_px = int(PAD_X * 2 + max_cols * CHAR_W) + 4

    for slug, lines, hi in snippets:
        svg = make_svg(lines, hi, width_px)
        (SVG_DIR / f"{slug}.svg").write_text(svg)
        print(f"wrote {slug}.svg  ({len(lines)} lines)")

    print(f"width={width_px}px (≈{max_cols} cols)")


if __name__ == "__main__":
    main()
