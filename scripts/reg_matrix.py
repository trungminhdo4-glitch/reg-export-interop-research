#!/usr/bin/env python3
"""Reproducible .reg export-matrix runner.

Seeds synthetic values under HKCU\\SOFTWARE\\REStudyTmp* ( PowerShell,
exact .NET types), exports every probe key with BOTH regedit.exe /e
and reg.exe export, parses both with reg_inspect.py, byte-compares the
emitters, and round-trips each export through reg.exe import into a
scratch tree (re-export + normalized semantic compare).

Scratch keys are removed at the end (absent -> absent); any failure
still attempts cleanup. Only stdlib. Windows required for
generation/oracle; parsing and diffing are platform-independent.
"""

import hashlib
import json
import os
import platform
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
INSPECT = os.path.join(HERE, "reg_inspect.py")
DIFF = os.path.join(HERE, "reg_diff.py")
SEED = os.path.join(HERE, "reg_seed.ps1")

ROOT = "HKCU\\SOFTWARE\\REStudyTmp"

# Environment operability (not under study): regedit.exe carries a
# requireAdministrator manifest, so every launch raises a UAC consent prompt
# and rapid successive launches get auto-denied ("durch den Benutzer
# abgebrochen"). Space launches out. Captured bytes are unaffected.
REGEDIT_SETTLE_SECONDS = 20

BIN30 = " ".join("%02x" % b for b in bytes(range(1, 31)))

# Probe = (id, changed_input, [values]). Types: REG_SZ/REG_EXPAND_SZ/
# REG_DWORD/REG_QWORD/REG_BINARY/REG_MULTI_SZ/SUBKEY (see reg_seed.ps1).
PROBES = [
    ("K00-baseline", "one REG_SZ", [{"name": "S", "type": "REG_SZ", "data": "hello"}]),
    (
        "K01-default",
        "default value",
        [{"name": "@", "type": "REG_SZ", "data": "defval"}],
    ),
    (
        "K02-dword",
        "REG_DWORD 42 and 0",
        [
            {"name": "N", "type": "REG_DWORD", "data": 42},
            {"name": "Z", "type": "REG_DWORD", "data": 0},
        ],
    ),
    (
        "K03-qword",
        "REG_QWORD 0x1122334455667788",
        [{"name": "Q", "type": "REG_QWORD", "data": 0x1122334455667788}],
    ),
    (
        "K04-binary8",
        "REG_BINARY 8 bytes single line",
        [{"name": "B", "type": "REG_BINARY", "data": "de ad be ef 00 11 22 33"}],
    ),
    (
        "K05-binary30",
        "REG_BINARY 30 bytes wrap probe",
        [{"name": "W", "type": "REG_BINARY", "data": BIN30}],
    ),
    (
        "K06-multisz",
        "REG_MULTI_SZ incl. empty element",
        [{"name": "M", "type": "REG_MULTI_SZ", "data": ["one", "", "two"]}],
    ),
    (
        "K07-expand",
        "REG_EXPAND_SZ unexpanded",
        [{"name": "E", "type": "REG_EXPAND_SZ", "data": "%REStudyTmp%\\sub"}],
    ),
    ("K08-empty", "key without values", []),
    (
        "K09-spaced-name",
        "value name with space",
        [{"name": "a b", "type": "REG_SZ", "data": "spaced"}],
    ),
    (
        "K10-subkey-order",
        "subkeys created c,a,b",
        [
            {"name": "v", "type": "REG_SZ", "data": "top"},
            {"name": "x", "type": "SUBKEY", "data": "subC", "with_value": True},
            {"name": "x", "type": "SUBKEY", "data": "subA", "with_value": True},
            {"name": "x", "type": "SUBKEY", "data": "subB", "with_value": True},
        ],
    ),
    (
        "K11-value-order",
        "values created zeta,alpha,mid",
        [
            {"name": "zeta", "type": "REG_SZ", "data": "1"},
            {"name": "alpha", "type": "REG_SZ", "data": "2"},
            {"name": "mid", "type": "REG_SZ", "data": "3"},
        ],
    ),
    (
        "K12-binary60",
        "REG_BINARY 60 bytes multi-wrap probe",
        [
            {
                "name": "W",
                "type": "REG_BINARY",
                "data": " ".join("%02x" % b for b in bytes(range(1, 61))),
            }
        ],
    ),
    (
        "K13-longname",
        "10-char value name shifts first wrap",
        [
            {
                "name": "0123456789",
                "type": "REG_BINARY",
                "data": " ".join("%02x" % b for b in bytes(range(1, 31))),
            }
        ],
    ),
    # R6 axis A: long-name prefix vs 77-column wrap. Same 30-byte payload as
    # K05/K13; prefix P = len(name)+7 ('"' + name + '"=hex:'). H-width predicts
    # first-line bytes = floor((77-P)/3): K14 P=27 -> 16; K15 P=76 -> 0;
    # K16 P=77 -> 0; K17 P=78 -> rule gives -1 (impossible: the boundary probe);
    # K18 P=107 -> long-prefix regime. Competing: H-width (break to 25/line
    # continuation) vs H-overflow (payload on the prefix line anyway).
    (
        "K14-wrapA0-name20",
        "20-char name interpolates floor model (P=27 -> 16 first-line bytes)",
        [
            {
                "name": "N" * 20,
                "type": "REG_BINARY",
                "data": " ".join("%02x" % b for b in bytes(range(1, 31))),
            }
        ],
    ),
    (
        "K15-wrapA1-p69",
        "69-char name just below 77-col prefix boundary (P=76 -> 0 bytes)",
        [
            {
                "name": "N" * 69,
                "type": "REG_BINARY",
                "data": " ".join("%02x" % b for b in bytes(range(1, 31))),
            }
        ],
    ),
    (
        "K16-wrapA2-p70",
        "70-char name at exact 77-col prefix boundary (P=77 -> 0 bytes)",
        [
            {
                "name": "N" * 70,
                "type": "REG_BINARY",
                "data": " ".join("%02x" % b for b in bytes(range(1, 31))),
            }
        ],
    ),
    (
        "K17-wrapA3-p71",
        "71-char name just above boundary (P=78: floor model undefined)",
        [
            {
                "name": "N" * 71,
                "type": "REG_BINARY",
                "data": " ".join("%02x" % b for b in bytes(range(1, 31))),
            }
        ],
    ),
    (
        "K18-wrapA4-p100",
        "100-char name long-prefix regime (P=107)",
        [
            {
                "name": "N" * 100,
                "type": "REG_BINARY",
                "data": " ".join("%02x" % b for b in bytes(range(1, 31))),
            }
        ],
    ),
    # R6 axis B: mixed-case ordering (ASCII only). B1: subkeys created
    # [b1,A1,B2,a2] (distinct folds). Ordinal predicts A1,B2,a2,b1;
    # case-folded-stable predicts A1,a2,b1,B2. B2: values created
    # [zeta,Alpha,MID,beta]; K11-model predicts creation order preserved
    # (any sorted order = asymmetry-rule divergence). Tie pairs (Ab vs aB)
    # are UNPRODUCIBLE: the namespace folds case at identity (proven in
    # scratch: one key survives) — documented, not probed.
    (
        "K19-orderB1-fold",
        "subkeys b1,A1,B2,a2 created scrambled: ordinal vs folded order",
        [
            {"name": "v", "type": "REG_SZ", "data": "top"},
            {"name": "x", "type": "SUBKEY", "data": "b1", "with_value": True},
            {"name": "x", "type": "SUBKEY", "data": "A1", "with_value": True},
            {"name": "x", "type": "SUBKEY", "data": "B2", "with_value": True},
            {"name": "x", "type": "SUBKEY", "data": "a2", "with_value": True},
        ],
    ),
    (
        "K20-orderB2-values",
        "values zeta,Alpha,MID,beta: creation order vs sorted (K11 scope)",
        [
            {"name": "zeta", "type": "REG_SZ", "data": "1"},
            {"name": "Alpha", "type": "REG_SZ", "data": "2"},
            {"name": "MID", "type": "REG_SZ", "data": "3"},
            {"name": "beta", "type": "REG_SZ", "data": "4"},
        ],
    ),
    # R6 axis C: REG_NONE (hex(0)) via .NET exact-type seeding (scratch-proven).
    # C1: 3-byte payload (discriminant preserved? agreement? round-trip?).
    # C2: empty payload (bare 'hex(0):' shape — agreement + round-trip?).
    (
        "K21-noneC1",
        "REG_NONE 3 bytes: hex(0) discriminant, agreement, round-trip",
        [{"name": "N", "type": "REG_NONE", "data": "01 02 03"}],
    ),
    (
        "K22-noneC2-empty",
        "REG_NONE empty: bare hex(0): shape, agreement, round-trip",
        [{"name": "E", "type": "REG_NONE", "data": ""}],
    ),
]


def run(cmd):
    proc = subprocess.run(cmd, capture_output=True, text=False, timeout=120)
    if proc.returncode != 0:
        err = (proc.stderr or b"")[-2000:].decode("utf-8", errors="replace")
        raise RuntimeError("command failed %r: %s" % (cmd, err))
    return (proc.stdout or b"").decode("utf-8-sig", errors="strict")


def shell():
    for candidate in ("pwsh", "powershell"):
        try:
            proc = subprocess.run(
                [candidate, "-NoProfile", "-Command", "1"],
                capture_output=True,
                timeout=30,
            )
            if proc.returncode == 0:
                return candidate
        except OSError:
            continue
    raise RuntimeError("no usable PowerShell found")


def reg(args):
    proc = subprocess.run(["reg"] + args, capture_output=True, timeout=120)
    if proc.returncode != 0:
        err = (proc.stderr or b"")[-1000:].decode("utf-8", errors="replace")
        raise RuntimeError("reg %s failed: %s" % (args, err))
    return proc


def inspect_file(path):
    return json.loads(run([sys.executable, INSPECT, path]))


def diff_docs(before_path, after_path):
    return json.loads(run([sys.executable, DIFF, before_path, after_path]))


def main(argv):
    work_root = argv[1] if len(argv) > 1 else "D:\\temp\\reg-matrix"
    outdir = argv[2] if len(argv) > 2 else os.path.join(work_root, "out")
    os.makedirs(work_root, exist_ok=True)
    os.makedirs(outdir, exist_ok=True)
    probes_dir = os.path.join(outdir, "probes")
    os.makedirs(probes_dir, exist_ok=True)
    powershell = shell()

    spec = {"probes": []}
    for pid, _changed, values in PROBES:
        spec["probes"].append({"key": "%s\\%s" % (ROOT, pid), "values": values})
    spec_path = os.path.join(work_root, "spec.json")
    with open(spec_path, "w", encoding="utf-8") as handle:
        json.dump(spec, handle, indent=2)

    subprocess.run(["reg", "delete", ROOT, "/f"], capture_output=True, timeout=60)
    try:
        run(
            [
                powershell,
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                SEED,
                "-SpecPath",
                spec_path,
            ]
        )
        results = []
        for pid, changed, _values in PROBES:
            key = "%s\\%s" % (ROOT, pid)
            # Fail fast with a clear cause if the seeded key is absent.
            probe = subprocess.run(
                ["reg", "query", key], capture_output=True, timeout=60
            )
            if probe.returncode != 0:
                raise RuntimeError("seeded key missing before export: %s" % key)
            edit_path = os.path.join(work_root, pid + ".regedit.reg")
            exe_path = os.path.join(work_root, pid + ".regexe.reg")
            time.sleep(REGEDIT_SETTLE_SECONDS)
            try:
                run(
                    [
                        powershell,
                        "-NoProfile",
                        "-Command",
                        'regedit /e "%s" "%s"'
                        % (edit_path, key.replace("HKCU\\", "HKEY_CURRENT_USER\\")),
                    ]
                )
            except RuntimeError:
                # regedit.exe launches can flake under rapid respawn;
                # one bounded retry before giving up.
                time.sleep(3)
                run(
                    [
                        powershell,
                        "-NoProfile",
                        "-Command",
                        'regedit /e "%s" "%s"'
                        % (edit_path, key.replace("HKCU\\", "HKEY_CURRENT_USER\\")),
                    ]
                )
            reg(["export", key, exe_path, "/y"])
            with open(edit_path, "rb") as handle:
                edit_blob = handle.read()
            with open(exe_path, "rb") as handle:
                exe_blob = handle.read()
            edit_doc = inspect_file(edit_path)
            exe_doc = inspect_file(exe_path)
            edit_json = os.path.join(probes_dir, pid + ".regedit.json")
            exe_json = os.path.join(probes_dir, pid + ".regexe.json")
            for path, doc in ((edit_json, edit_doc), (exe_json, exe_doc)):
                with open(path, "w", encoding="utf-8") as handle:
                    json.dump(doc, handle, indent=2, sort_keys=True)
                    handle.write("\n")
            # Round-trip oracle: delete the seeded key, re-import the
            # regedit export, re-export, compare bytes and model.
            # Import fidelity is the claim under test (import-time
            # normalization, e.g. MULTI_SZ edges, would show up here).
            reg(["delete", key, "/f"])
            reg(["import", edit_path])
            rt_path = os.path.join(work_root, pid + ".roundtrip.reg")
            reg(["export", key, rt_path, "/y"])
            with open(rt_path, "rb") as handle:
                rt_blob = handle.read()
            rt_doc = inspect_file(rt_path)
            rt_json = os.path.join(probes_dir, pid + ".roundtrip.json")
            with open(rt_json, "w", encoding="utf-8") as handle:
                json.dump(rt_doc, handle, indent=2, sort_keys=True)
                handle.write("\n")
            sections = [
                {
                    "key": s["key"].split("\\")[-1],
                    "values": [
                        {"name": v["name"], "kind": v["kind"]} for v in s["values"]
                    ],
                }
                for s in edit_doc["sections"]
            ]
            results.append(
                {
                    "probe": pid,
                    "changed_input": changed,
                    "regedit_sha256": hashlib.sha256(edit_blob).hexdigest(),
                    "regexe_sha256": hashlib.sha256(exe_blob).hexdigest(),
                    "byte_identical": edit_blob == exe_blob,
                    "emitter_semantic_delta": diff_docs(edit_json, exe_json),
                    "roundtrip_byte_identical": rt_blob == edit_blob,
                    "roundtrip_clean": rt_doc == edit_doc,
                    "sections": sections,
                }
            )
    finally:
        subprocess.run(["reg", "delete", ROOT, "/f"], capture_output=True, timeout=60)

    try:
        ps_version = run(
            [
                powershell,
                "-NoProfile",
                "-Command",
                "$PSVersionTable.PSVersion.ToString()",
            ]
        ).strip()
    except RuntimeError:
        ps_version = "unknown"
    matrix = {
        "study": "reg-export-matrix",
        "spec": "Registry Editor Version 5.00 exports",
        "generators": ["regedit.exe /e", "reg.exe export"],
        "oracle": "reg.exe import into scratch tree + re-export",
        "environment": {
            "os": platform.platform(),
            "windows_build": platform.version(),
            "powershell": "%s %s" % (powershell, ps_version),
            "python": platform.python_version(),
        },
        "probes": results,
    }
    with open(os.path.join(outdir, "matrix.json"), "w", encoding="utf-8") as handle:
        json.dump(matrix, handle, indent=2, sort_keys=True)
        handle.write("\n")
    n_ident = sum(1 for r in results if r["byte_identical"])
    n_rt = sum(1 for r in results if r["roundtrip_clean"])
    print(
        "probes=%d byte_identical=%d/%d roundtrip_clean=%d/%d outdir=%s"
        % (len(results), n_ident, len(results), n_rt, len(results), outdir)
    )


if __name__ == "__main__":
    main(sys.argv)
