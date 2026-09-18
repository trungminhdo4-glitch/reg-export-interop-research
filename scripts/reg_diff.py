#!/usr/bin/env python3
"""Semantic differ for two reg_inspect.py JSON documents.

Compares the parsed key/value model (order-sensitive: export order is
part of the evidence) and reports byte-level identity separately.

Usage: reg_diff.py <before.json> <after.json>
Exit codes: 0 = compared, 2 = usage/IO. Stdlib only.
"""

import json
import sys

EXIT_OK = 0
EXIT_USAGE = 2


def value_key(value):
    return "@" if value["name"] is None else value["name"]


def diff(before, after):
    deltas = []
    if before["text_sha256"] != after["text_sha256"]:
        deltas.append(
            {
                "path": "<bytes>",
                "kind": "changed",
                "before": before["text_sha256"],
                "after": after["text_sha256"],
            }
        )
    sections_before = {s["key"]: s for s in before["sections"]}
    sections_after = {s["key"]: s for s in after["sections"]}
    order_before = [s["key"] for s in before["sections"]]
    order_after = [s["key"] for s in after["sections"]]
    if order_before != order_after:
        deltas.append(
            {
                "path": "<section-order>",
                "kind": "changed",
                "before": order_before,
                "after": order_after,
            }
        )
    for key in sorted(set(sections_before) | set(sections_after)):
        if key not in sections_before:
            deltas.append(
                {
                    "path": key,
                    "kind": "added",
                    "before": "<ABSENT>",
                    "after": sections_after[key]["values"],
                }
            )
            continue
        if key not in sections_after:
            deltas.append(
                {
                    "path": key,
                    "kind": "removed",
                    "before": sections_before[key]["values"],
                    "after": "<ABSENT>",
                }
            )
            continue
        vals_before = {value_key(v): v for v in sections_before[key]["values"]}
        vals_after = {value_key(v): v for v in sections_after[key]["values"]}
        order_b = [value_key(v) for v in sections_before[key]["values"]]
        order_a = [value_key(v) for v in sections_after[key]["values"]]
        if order_b != order_a:
            deltas.append(
                {
                    "path": "%s.<value-order>" % key,
                    "kind": "changed",
                    "before": order_b,
                    "after": order_a,
                }
            )
        for name in sorted(set(vals_before) | set(vals_after)):
            path = "%s.%s" % (key, name)
            if name not in vals_before:
                deltas.append(
                    {
                        "path": path,
                        "kind": "added",
                        "before": "<ABSENT>",
                        "after": vals_after[name],
                    }
                )
            elif name not in vals_after:
                deltas.append(
                    {
                        "path": path,
                        "kind": "removed",
                        "before": vals_before[name],
                        "after": "<ABSENT>",
                    }
                )
            elif vals_before[name] != vals_after[name]:
                deltas.append(
                    {
                        "path": path,
                        "kind": "changed",
                        "before": vals_before[name],
                        "after": vals_after[name],
                    }
                )
    return deltas


def main(argv):
    if len(argv) != 3 or argv[1] in ("-h", "--help"):
        sys.stderr.write("usage: reg_diff.py <before.json> <after.json>\n")
        return EXIT_USAGE
    try:
        with open(argv[1], encoding="utf-8") as handle:
            before = json.load(handle)
        with open(argv[2], encoding="utf-8") as handle:
            after = json.load(handle)
    except (OSError, ValueError) as exc:
        sys.stderr.write("error: cannot load inputs: %s\n" % exc)
        return EXIT_USAGE
    sys.stdout.write(json.dumps(diff(before, after), indent=2, sort_keys=True) + "\n")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main(sys.argv))
