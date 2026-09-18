# Windows Registry export (.reg v5) canonicalization matrix

Which registry shapes canonicalize to which exact `.reg` text — and
whether `regedit.exe /e` and `reg.exe export` ever disagree. Measured
against the real Windows emitters with byte evidence. Own work only:
our scripts, our synthetic scratch keys, our measurements. No user
keys touched, no binary artifacts committed.

## Scope

- IN: v5 exports of synthetic `HKCU\SOFTWARE\REStudyTmp*` keys
  (absent→absent per run); 6 value types + defaults + empty keys +
  ordering probes; strict read-only inspector; normalizing differ;
  import round-trip oracle.
- OUT: writing/deploying .reg files, HKLM/other hives, user data,
  exploit-adjacent registry content.

## Provenance

- Emitters: `regedit.exe /e` + `reg.exe export`, Windows 10 Home
  build 26200. Corpus set via PowerShell/.NET exact types.
- Prior art: prose .reg descriptions, forensic parsers. Gap: no
  canonical differential — wrap rule, ordering, emitter equivalence.

## Research questions

1. Which value type encodes how — exactly (padding, case, byte order)?
2. At what width do hex lines wrap, and what shifts the break?
3. Are subkeys/values exported sorted or in creation order?
4. Do the two emitters ever diverge? Does import normalize anything?

## Method

1. `scripts/reg_inspect.py` — strict v5 parser, deterministic JSON,
   exit 3 on malformed (stdlib only).
2. `scripts/reg_seed.ps1` — confined exact-type seeder.
3. `scripts/reg_matrix.py` — 14 probes × 2 emitters + round-trips →
   `matrix.json`.
4. `scripts/reg_diff.py` — semantic differ.
5. `tests/test_reg_study.py` — 20 platform-independent unit tests.

Details + hypotheses/falsifiers: `RESEARCH.md`. Machine claims:
`findings.json`. Evidence: `matrix.json` (regenerate on Windows with
`python scripts/reg_matrix.py <workroot> <outdir>`).

## Findings (short)

- Emitters: 14/14 BYTE-IDENTICAL. Round-trips: 14/14 byte-identical.
- `dword:` = 8 lowercase hex; QWORD = `hex(b)` LE bytes.
- Hex wrap = 77 content columns (`\` + 2-space indent, comma kept).
- Subkeys alphabetical; values in creation order (asymmetry).
- Empty MULTI_SZ elements and unexpanded EXPAND_SZ survive round-trip.

## Reproduce

```powershell
python scripts/reg_matrix.py D:\temp\reg-matrix D:\temp\reg-matrix\out
python -m pytest tests -q   # no Windows needed
```

## Safety & privacy

Synthetic scratch keys only (`REStudyTmp*`, removed after runs);
import oracle only re-imports our own fresh exports. `matrix.json`
holds no user paths/SIDs/machine data; no binaries committed.

## Prior art

MS .reg prose docs, blog transcriptions, forensic parsers. Gap under
study: emitter equivalence + canonicalization rules. See `RESEARCH.md`.

## License

MIT — see `LICENSE` (public mirror).

## Non-affiliation

Independent format-interop research. Not affiliated with, sponsored,
or endorsed by Microsoft. Windows is a trademark of Microsoft.
