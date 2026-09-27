"""Unit tests for the reg-export-matrix study (no Windows required).

All fixtures are hand-built synthetic .reg text; no real exports committed.
Run: pytest tests/test_reg_study.py
"""

import json
import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(HERE, "..", "scripts")
sys.path.insert(0, os.path.abspath(SCRIPTS))

import reg_diff
import reg_inspect
from reg_inspect import Malformed, inspect

HEADER = "Windows Registry Editor Version 5.00"


def blob(text):
    return ("﻿" + text).encode("utf-16le")


def minimal(sz="hello"):
    return blob(
        '%s\r\n\r\n[HKEY_CURRENT_USER\\SOFTWARE\\X]\r\n"S"="%s"\r\n\r\n' % (HEADER, sz)
    )


def test_valid_minimal():
    doc = inspect(minimal())
    assert doc["header"] == HEADER
    assert doc["line_ending"] == "CRLF"
    assert doc["section_count"] == 1
    value = doc["sections"][0]["values"][0]
    assert (value["name"], value["kind"], value["value"]) == ("S", "REG_SZ", "hello")


def test_missing_bom_rejected():
    with pytest.raises(Malformed):
        inspect(minimal().lstrip(b"\xff\xfe"))


def test_bad_header_rejected():
    with pytest.raises(Malformed):
        inspect(blob("nonsense\r\n"))


def test_dword_decoded():
    doc = inspect(blob('%s\r\n\r\n[K]\r\n"N"=dword:0000002a\r\n' % HEADER))
    value = doc["sections"][0]["values"][0]
    assert (value["kind"], value["value"]) == ("REG_DWORD", 42)


def test_dword_bad_length_rejected():
    with pytest.raises(Malformed):
        inspect(blob('%s\r\n\r\n[K]\r\n"N"=dword:2a\r\n' % HEADER))


def test_qword_letter_discriminant():
    doc = inspect(
        blob('%s\r\n\r\n[K]\r\n"Q"=hex(b):88,77,66,55,44,33,22,11\r\n' % HEADER)
    )
    value = doc["sections"][0]["values"][0]
    assert value["kind"] == "REG_QWORD"
    assert value["value"] == 0x1122334455667788


def test_binary_and_wrap_continuation():
    doc = inspect(blob('%s\r\n\r\n[K]\r\n"W"=hex:01,02,\\\r\n  03,04\r\n' % HEADER))
    value = doc["sections"][0]["values"][0]
    assert value["kind"] == "REG_BINARY"
    assert value["bytes_hex"] == "01020304"


def test_unterminated_continuation_rejected():
    with pytest.raises(Malformed):
        inspect(blob('%s\r\n\r\n[K]\r\n"W"=hex:01,\\\r\n' % HEADER))


def test_odd_hex_rejected():
    with pytest.raises(Malformed):
        inspect(blob('%s\r\n\r\n[K]\r\n"W"=hex:0,1,2\r\n' % HEADER))


def test_multisz_empty_element_kept_terminator_framing_dropped():
    # ["one", ""] on the wire: "one\0" + "\0" + terminator "\0".
    payload = "6f,00,6e,00,65,00,00,00,00,00,00,00"
    doc = inspect(blob('%s\r\n\r\n[K]\r\n"M"=hex(7):%s\r\n' % (HEADER, payload)))
    value = doc["sections"][0]["values"][0]
    assert value["kind"] == "REG_MULTI_SZ"
    assert value["value"] == ["one", ""]


def test_multisz_missing_terminator_rejected():
    with pytest.raises(Malformed):
        inspect(blob('%s\r\n\r\n[K]\r\n"M"=hex(7):6f,00,6e,00,65,00\r\n' % HEADER))


def test_expand_terminator_handling():
    payload = "25,00,78,00,00,00"  # "%x" + NUL
    doc = inspect(blob('%s\r\n\r\n[K]\r\n"E"=hex(2):%s\r\n' % (HEADER, payload)))
    value = doc["sections"][0]["values"][0]
    assert value["kind"] == "REG_EXPAND_SZ"
    assert value["value"] == "%x"
    assert value["terminated"] is True


def test_default_and_delete_markers():
    doc = inspect(blob('%s\r\n\r\n[K]\r\n@="d"\r\n"Gone"=-\r\n' % HEADER))
    values = {v["name"]: v for v in doc["sections"][0]["values"]}
    assert values[None]["kind"] == "REG_SZ"
    assert values["Gone"]["kind"] == "DELETE"


def test_key_deletion_section():
    doc = inspect(blob("%s\r\n\r\n[-K\\Sub]\r\n" % HEADER))
    assert doc["sections"][0]["deleted"] is True


def test_value_outside_section_rejected():
    with pytest.raises(Malformed):
        inspect(blob('%s\r\n\r\n"S"="x"\r\n' % HEADER))


def test_unknown_hex_inventoried():
    doc = inspect(blob('%s\r\n\r\n[K]\r\n"U"=hex(9):01,02\r\n' % HEADER))
    value = doc["sections"][0]["values"][0]
    assert value["kind"] == "UNKNOWN_HEX_9"
    assert value["known_type"] is False


def test_unknown_hex_0_inventoried():
    # R6-C consumer shape only: the inspector must inventory a hex(0)
    # (REG_NONE) payload without claiming its producer semantics.
    # Producer behavior comes from the Windows matrix run, not this test.
    doc = inspect(blob('%s\r\n\r\n[K]\r\n"N"=hex(0):01,02,03\r\n' % HEADER))
    value = doc["sections"][0]["values"][0]
    assert value["kind"] == "UNKNOWN_HEX_0"
    assert value["known_type"] is False
    assert value["bytes_hex"] == "010203"


def test_bare_hex_0_empty_payload_shape():
    # R6-C2 consumer shape only: bare 'hex(0):' with no payload bytes.
    doc = inspect(blob('%s\r\n\r\n[K]\r\n"E"=hex(0):\r\n' % HEADER))
    value = doc["sections"][0]["values"][0]
    assert value["kind"] == "UNKNOWN_HEX_0"
    assert value["bytes_hex"] == ""


def test_long_name_continuation_joins():
    # R6-A consumer shape only: a 100-char value name with a wrapped
    # payload must join to one logical line; width claims need the matrix.
    name = "N" * 100
    text = '%s\r\n\r\n[K]\r\n"%s"=hex:01,02,\\\r\n  03,04\r\n' % (HEADER, name)
    doc = inspect(blob(text))
    value = doc["sections"][0]["values"][0]
    assert value["name"] == name
    assert value["bytes_hex"] == "01020304"


def test_section_order_preserved_as_emitted():
    # The inspector model preserves emission order verbatim (mixed-case
    # section names included); ordering verdicts therefore describe the
    # emitter, and this test pins the preservation, not any rule.
    text = '%s\r\n\r\n[b1]\r\n@="t"\r\n[B2]\r\n@="t"\r\n' % HEADER
    doc = inspect(blob(text))
    keys = [s["key"] for s in doc["sections"]]
    assert keys == ["b1", "B2"]


def test_bad_escape_rejected():
    with pytest.raises(Malformed):
        inspect(blob('%s\r\n\r\n[K]\r\n"S"="a\\qb"\r\n' % HEADER))


def test_diff_empty_for_identical():
    doc = inspect(minimal())
    assert reg_diff.diff(doc, doc) == []


def test_diff_reports_semantic_and_order_changes():
    before = inspect(minimal("a"))
    after = inspect(
        blob(
            "%s\r\n\r\n[HKEY_CURRENT_USER\\SOFTWARE\\X]\r\n"
            '"S"="b"\r\n"T"=dword:00000001\r\n\r\n' % HEADER
        )
    )
    paths = {d["path"]: d for d in reg_diff.diff(before, after)}
    assert paths["HKEY_CURRENT_USER\\SOFTWARE\\X.S"]["kind"] == "changed"
    assert paths["HKEY_CURRENT_USER\\SOFTWARE\\X.T"]["kind"] == "added"
    assert "HKEY_CURRENT_USER\\SOFTWARE\\X.<value-order>" in paths


def _run_cli(script, *args):
    cmd = [sys.executable, os.path.join(SCRIPTS, script)] + list(args)
    return subprocess.run(cmd, capture_output=True, timeout=60)


def test_cli_exit_codes(tmp_path):
    good = tmp_path / "good.reg"
    good.write_bytes(minimal())
    proc = _run_cli("reg_inspect.py", str(good))
    assert proc.returncode == 0
    assert json.loads(proc.stdout)["section_count"] == 1

    bad = tmp_path / "bad.reg"
    bad.write_bytes(b"nope")
    assert _run_cli("reg_inspect.py", str(bad)).returncode == 3
    assert _run_cli("reg_inspect.py", str(tmp_path / "m.reg")).returncode == 2

    first = tmp_path / "a.json"
    first.write_bytes(_run_cli("reg_inspect.py", str(good)).stdout)
    proc = _run_cli("reg_diff.py", str(first), str(first))
    assert proc.returncode == 0
    assert json.loads(proc.stdout) == []
