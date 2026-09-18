#!/usr/bin/env python3
"""Strict structural inspector for Windows Registry Editor export (.reg v5).

Scope: `Windows Registry Editor Version 5.00` files (UTF-16LE + BOM),
as emitted by regedit.exe /e and reg.exe export. Parses sections,
value assignments (REG_SZ/DWORD/BINARY/QWORD/MULTI_SZ/EXPAND_SZ),
deletion markers, and backslash continuations into deterministic JSON.

Exit codes: 0 = parsed, 2 = usage/IO, 3 = malformed.
Stdlib only.
"""

import hashlib
import json
import struct
import sys

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_MALFORMED = 3

BOM_UTF16LE = b"\xff\xfe"
HEADER_LINE = "Windows Registry Editor Version 5.00"

# hex(N) discriminants in v5 exports (others inventoried, not rejected).
HEX_KIND = {
    None: "REG_BINARY",
    "2": "REG_EXPAND_SZ",
    "7": "REG_MULTI_SZ",
    "b": "REG_QWORD",
}


class Malformed(Exception):
    """Raised with a line-anchored reason when text violates the v5 shape."""


def split_logical_lines(text):
    """Join backslash continuations; return [(lineno, logical_line)]."""
    physical = text.splitlines()
    logical = []
    buf = ""
    start = 0
    for index, raw in enumerate(physical, start=1):
        line = raw.rstrip("\r\n")
        if line.endswith("\\"):
            if not buf:
                start = index
            buf += line[:-1]
            continue
        if buf:
            logical.append((start, buf + line))
            buf = ""
        else:
            logical.append((index, line))
    if buf:
        raise Malformed("line %d: unterminated backslash continuation" % start)
    return logical


def decode_quoted(token, lineno):
    if len(token) < 2 or not token.startswith('"'):
        raise Malformed("line %d: bad quoted string" % lineno)
    out = []
    pos = 1
    while pos < len(token):
        char = token[pos]
        if char == "\\":
            pos += 1
            if pos >= len(token) or token[pos] not in ('"', "\\"):
                raise Malformed("line %d: bad escape in string" % lineno)
            out.append(token[pos])
        elif char == '"':
            if pos != len(token) - 1:
                raise Malformed("line %d: trailing text after string" % lineno)
            return "".join(out)
        else:
            out.append(char)
        pos += 1
    raise Malformed("line %d: unterminated string" % lineno)


def parse_hex_payload(payload, lineno):
    digits = "".join(payload.replace(",", "").split())
    if len(digits) % 2 != 0:
        raise Malformed("line %d: odd hex digit count" % lineno)
    try:
        return bytes.fromhex(digits)
    except ValueError:
        raise Malformed("line %d: non-hex digits in hex payload" % lineno)


def parse_value_rhs(rhs, lineno) -> dict:
    if rhs == "-":
        return {"kind": "DELETE", "raw": rhs}
    if rhs.startswith('"'):
        return {"kind": "REG_SZ", "value": decode_quoted(rhs, lineno), "raw": rhs}
    if rhs.startswith("dword:"):
        digits = rhs[len("dword:") :]
        if len(digits) != 8:
            raise Malformed("line %d: dword needs 8 hex digits" % lineno)
        try:
            number = int(digits, 16)
        except ValueError:
            raise Malformed("line %d: non-hex dword" % lineno)
        return {"kind": "REG_DWORD", "value": number, "raw": rhs}
    if rhs.startswith("hex"):
        rest = rhs[len("hex") :]
        discriminant = None
        if rest.startswith("("):
            end = rest.find(")")
            token = rest[1:end] if end != -1 else ""
            if token == "":
                raise Malformed("line %d: bad hex discriminant" % lineno)
            discriminant = token
            rest = rest[end + 1 :]
        if not rest.startswith(":"):
            raise Malformed("line %d: bad hex assignment" % lineno)
        blob = parse_hex_payload(rest[1:], lineno)
        kind = HEX_KIND.get(discriminant, "UNKNOWN_HEX_%s" % discriminant)
        entry = {"kind": kind, "bytes_hex": blob.hex(), "raw": rhs}
        if discriminant is not None and discriminant not in HEX_KIND:
            entry["known_type"] = False
        if kind == "REG_QWORD":
            if len(blob) != 8:
                raise Malformed("line %d: qword needs 8 bytes" % lineno)
            entry["value"] = struct.unpack("<Q", blob)[0]
        elif kind == "REG_EXPAND_SZ":
            entry["terminated"] = blob.endswith(b"\x00\x00")
            core = blob[:-2] if entry["terminated"] else blob
            entry["value"] = core.decode("utf-16le", errors="strict")
        elif kind == "REG_MULTI_SZ":
            if not blob.endswith(b"\x00\x00"):
                raise Malformed("line %d: multi_sz missing terminator" % lineno)
            text = blob[:-2].decode("utf-16le", errors="strict")
            parts = text.split("\x00")
            # The terminator-adjacent empty element is framing, not data.
            entry["value"] = parts[:-1] if parts and parts[-1] == "" else parts
        return entry
    raise Malformed("line %d: unknown value form" % lineno)


def parse_name_lhs(lhs, lineno):
    if lhs == "@":
        return None  # default value
    return decode_quoted(lhs, lineno)


def inspect_text(text):
    logical = split_logical_lines(text)
    if not logical or logical[0][1] != HEADER_LINE:
        raise Malformed("line 1: missing v5 header")
    sections = []
    current = None
    for lineno, line in logical[1:]:
        if line == "":
            continue
        if line.startswith("["):
            if not line.endswith("]"):
                raise Malformed("line %d: unterminated section" % lineno)
            path = line[1:-1]
            if path.startswith("-"):
                sections.append({"key": path[1:], "deleted": True, "values": []})
                current = None
            else:
                current = {"key": path, "deleted": False, "values": []}
                sections.append(current)
            continue
        if current is None:
            raise Malformed("line %d: value outside any section" % lineno)
        if "=" not in line:
            raise Malformed("line %d: bad value line" % lineno)
        lhs, rhs = line.split("=", 1)
        value = parse_value_rhs(rhs, lineno)
        value["name"] = parse_name_lhs(lhs, lineno)
        current["values"].append(value)
    return {
        "format": "REGEDIT5",
        "header": HEADER_LINE,
        "sections": sections,
        "section_count": len(sections),
    }


def inspect(data):
    if not data.startswith(BOM_UTF16LE):
        raise Malformed("missing UTF-16LE BOM (v5 scope only)")
    try:
        text = data.decode("utf-16le")
    except UnicodeDecodeError as exc:
        raise Malformed("UTF-16LE decode error: %s" % exc)
    if text.startswith("\ufeff"):
        text = text[1:]  # byte-level BOM already required above
    else:
        raise Malformed("missing BOM character after BOM bytes")
    if "\x00" in text[1:]:
        raise Malformed("NUL byte inside decoded text")
    doc = inspect_text(text)
    doc["text_sha256"] = hashlib.sha256(data).hexdigest()
    doc["byte_size"] = len(data)
    # Text-level check: in UTF-16LE bytes CRLF is 0D 00 0A 00.
    doc["line_ending"] = "CRLF" if "\r\n" in text else "LF"
    return doc


def main(argv):
    if len(argv) != 2 or argv[1] in ("-h", "--help"):
        sys.stderr.write("usage: reg_inspect.py <file.reg>\n")
        return EXIT_USAGE
    try:
        with open(argv[1], "rb") as handle:
            data = handle.read()
    except OSError as exc:
        sys.stderr.write("error: cannot read input: %s\n" % exc)
        return EXIT_USAGE
    try:
        result = inspect(data)
    except Malformed as exc:
        sys.stderr.write("error: malformed reg: %s\n" % exc)
        return EXIT_MALFORMED
    except UnicodeDecodeError as exc:
        sys.stderr.write("error: malformed reg: %s\n" % exc)
        return EXIT_MALFORMED
    sys.stdout.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main(sys.argv))
