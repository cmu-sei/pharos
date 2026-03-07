#!/usr/bin/env python3
import argparse
import json
import pathlib
import re
import shutil
import subprocess
import sys


def pick_readelf() -> str | None:
    for name in ("readelf", "llvm-readelf", "greadelf"):
        path = shutil.which(name)
        if path:
            return path
    return None


def run_readelf_symbols(readelf_bin: str, binary: pathlib.Path) -> str:
    proc = subprocess.run(
        [readelf_bin, "-Ws", str(binary)],
        check=True,
        text=True,
        capture_output=True,
    )
    return proc.stdout


def analyze_symbols(text: str) -> dict:
    zti = set(re.findall(r"\b_ZTI[^\s@]*", text))
    ztv = set(re.findall(r"\b_ZTV[^\s@]*", text))
    zts = set(re.findall(r"\b_ZTS[^\s@]*", text))

    demangled_typeinfo = len(re.findall(r"typeinfo for ", text))
    demangled_vtable = len(re.findall(r"vtable for ", text))
    cxxabi_typeinfo = len(re.findall(r"__cxxabiv1::__", text))

    score = len(zti) + len(ztv) + len(zts) + demangled_typeinfo + demangled_vtable + cxxabi_typeinfo
    has_rtti = score > 0

    return {
        "has_rtti": has_rtti,
        "score": score,
        "counts": {
            "_ZTI": len(zti),
            "_ZTV": len(ztv),
            "_ZTS": len(zts),
            "demangled_typeinfo": demangled_typeinfo,
            "demangled_vtable": demangled_vtable,
            "cxxabi_typeinfo": cxxabi_typeinfo,
        },
        "examples": {
            "_ZTI": sorted(zti)[:5],
            "_ZTV": sorted(ztv)[:5],
            "_ZTS": sorted(zts)[:5],
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Quick RTTI presence check for ELF binaries")
    parser.add_argument("binary", help="Path to ELF binary")
    parser.add_argument("--json", action="store_true", help="Emit JSON output")
    args = parser.parse_args()

    binary = pathlib.Path(args.binary).expanduser().resolve()
    if not binary.exists():
        print(f"error: binary not found: {binary}", file=sys.stderr)
        return 2

    readelf_bin = pick_readelf()
    if not readelf_bin:
        msg = {
            "ok": False,
            "reason": "No readelf tool found (readelf/llvm-readelf/greadelf)",
            "binary": str(binary),
        }
        if args.json:
            print(json.dumps(msg))
        else:
            print(msg["reason"])
        return 1

    try:
        text = run_readelf_symbols(readelf_bin, binary)
    except subprocess.CalledProcessError as exc:
        msg = {
            "ok": False,
            "reason": "readelf failed",
            "binary": str(binary),
            "stderr": exc.stderr[-5000:] if exc.stderr else "",
        }
        if args.json:
            print(json.dumps(msg))
        else:
            print(f"readelf failed for {binary}")
        return 1

    analysis = analyze_symbols(text)
    out = {
        "ok": True,
        "binary": str(binary),
        "tool": readelf_bin,
        **analysis,
    }

    if args.json:
        print(json.dumps(out))
    else:
        status = "likely present" if out["has_rtti"] else "not obvious"
        print(f"RTTI: {status}")
        print(f"  _ZTI={out['counts']['_ZTI']} _ZTV={out['counts']['_ZTV']} _ZTS={out['counts']['_ZTS']}")
        print(f"  demangled typeinfo={out['counts']['demangled_typeinfo']} vtable={out['counts']['demangled_vtable']}")
        if out["examples"]["_ZTI"]:
            print(f"  example _ZTI: {out['examples']['_ZTI'][0]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
