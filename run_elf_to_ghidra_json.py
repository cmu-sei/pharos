#!/usr/bin/env python3
import argparse
import datetime
import json
import pathlib
import re
import shutil
import struct
import subprocess
import sys


HEX_ADDR_RE = re.compile(r"^0x[0-9a-fA-F]+$")
CLASS_ADDR_RE = re.compile(r"^cls_0x([0-9a-fA-F]+)$")


def log(message: str) -> None:
    now = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{now}] {message}", flush=True)


def parse_int(value: str) -> int:
    return int(value.strip(), 0)


def parse_ghidra_map_line(line: str) -> int:
    tokens = line.strip().split()
    if len(tokens) < 2:
        raise ValueError("Ghidra map line does not contain a start address")
    return int(tokens[1], 16)


def prompt_if_missing(value: str, prompt: str) -> str:
    if value:
        return value
    answer = input(prompt).strip()
    if not answer:
        raise ValueError("A value is required")
    return answer


def resolve_ghidra_text_start(raw_value: str) -> int:
    try:
        return parse_int(raw_value)
    except ValueError:
        return parse_ghidra_map_line(raw_value)


def read_elf_text_vaddr(binary_path: pathlib.Path) -> int:
    data = binary_path.read_bytes()
    if data[:4] != b"\x7fELF":
        raise ValueError(f"Not an ELF file: {binary_path}")

    ei_class = data[4]
    ei_data = data[5]
    if ei_class not in (1, 2):
        raise ValueError("Unsupported ELF class")
    if ei_data == 1:
        endian = "<"
    elif ei_data == 2:
        endian = ">"
    else:
        raise ValueError("Unsupported ELF endianness")

    if ei_class == 1:
        ehdr_fmt = endian + "16sHHIIIIIHHHHHH"
        shdr_fmt = endian + "IIIIIIIIII"
    else:
        ehdr_fmt = endian + "16sHHIQQQIHHHHHH"
        shdr_fmt = endian + "IIQQQQIIQQ"

    ehdr_size = struct.calcsize(ehdr_fmt)
    eh = struct.unpack(ehdr_fmt, data[:ehdr_size])
    e_shoff = eh[6]
    e_shentsize = eh[11]
    e_shnum = eh[12]
    e_shstrndx = eh[13]

    if e_shoff == 0 or e_shnum == 0:
        raise ValueError("ELF has no section headers")

    shdr_size = struct.calcsize(shdr_fmt)
    if e_shentsize < shdr_size:
        raise ValueError("Unexpected section header size")

    section_headers = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh = struct.unpack(shdr_fmt, data[off:off + shdr_size])
        section_headers.append(sh)

    shstr = section_headers[e_shstrndx]
    shstr_off, shstr_size = shstr[4], shstr[5]
    shstrtab = data[shstr_off:shstr_off + shstr_size]

    def read_cstr(blob: bytes, start: int) -> str:
        end = blob.find(b"\x00", start)
        if end == -1:
            end = len(blob)
        return blob[start:end].decode("utf-8", errors="replace")

    for sh in section_headers:
        name = read_cstr(shstrtab, sh[0])
        if name == ".text":
            return sh[3]

    raise ValueError("Could not find .text section in ELF")


def shift_hex_string(s: str, bias: int) -> str:
    value = int(s, 16)
    shifted = value + bias
    if shifted < 0:
        raise ValueError(f"Shift would make negative address: {s} + {bias}")
    return f"0x{shifted:x}"


def maybe_shift_addr(s: str, bias: int) -> str:
    return shift_hex_string(s, bias) if HEX_ADDR_RE.match(s) else s


def rebase_json(doc: dict, bias: int) -> dict:
    structures = doc.get("structures", {})
    new_structures = {}

    for cls_key, cls in structures.items():
        new_cls_key = cls_key
        m = CLASS_ADDR_RE.match(cls_key)
        if m:
            raw = int(m.group(1), 16)
            new_cls_key = f"cls_0x{raw + bias:x}"

        cls_obj = dict(cls)
        name = cls_obj.get("name")
        if isinstance(name, str):
            m_name = CLASS_ADDR_RE.match(name)
            if m_name:
                raw = int(m_name.group(1), 16)
                cls_obj["name"] = f"cls_0x{raw + bias:x}"

        methods = cls_obj.get("methods", {})
        new_methods = {}
        for meth_key, meth in methods.items():
            new_key = maybe_shift_addr(meth_key, bias)
            meth_obj = dict(meth)
            if isinstance(meth_obj.get("ea"), str):
                meth_obj["ea"] = maybe_shift_addr(meth_obj["ea"], bias)
            new_methods[new_key] = meth_obj
        cls_obj["methods"] = new_methods

        vftables = cls_obj.get("vftables", {})
        new_vftables = {}
        for vft_key, vft in vftables.items():
            new_vft_key = maybe_shift_addr(vft_key, bias)
            vft_obj = dict(vft)
            if isinstance(vft_obj.get("ea"), str):
                vft_obj["ea"] = maybe_shift_addr(vft_obj["ea"], bias)
            entries = vft_obj.get("entries", {})
            new_entries = {}
            for ent_key, ent in entries.items():
                ent_obj = dict(ent)
                if isinstance(ent_obj.get("ea"), str):
                    ent_obj["ea"] = maybe_shift_addr(ent_obj["ea"], bias)
                new_entries[ent_key] = ent_obj
            vft_obj["entries"] = new_entries
            new_vftables[new_vft_key] = vft_obj
        cls_obj["vftables"] = new_vftables

        new_structures[new_cls_key] = cls_obj

    doc["structures"] = new_structures

    vcalls = doc.get("vcalls", {})
    new_vcalls = {}
    for call_key, call in vcalls.items():
        new_call_key = maybe_shift_addr(call_key, bias)
        call_obj = dict(call)
        targets = call_obj.get("targets", [])
        call_obj["targets"] = [maybe_shift_addr(t, bias) if isinstance(t, str) else t for t in targets]
        new_vcalls[new_call_key] = call_obj
    doc["vcalls"] = new_vcalls

    return doc


def summarize(json_doc: dict) -> dict:
    structures = json_doc.get("structures", {})
    vcalls = json_doc.get("vcalls", {})
    class_count = len(structures)
    method_count = sum(len(c.get("methods", {})) for c in structures.values())
    vftable_count = sum(len(c.get("vftables", {})) for c in structures.values())
    vft_entry_count = 0
    for cls in structures.values():
        for vft in cls.get("vftables", {}).values():
            vft_entry_count += len(vft.get("entries", {}))
    return {
        "class_count": class_count,
        "method_count": method_count,
        "vftable_count": vftable_count,
        "vft_entry_count": vft_entry_count,
        "vcall_count": len(vcalls),
    }


def run_command(cmd: list[str]) -> None:
    log("Running: " + " ".join(cmd))
    subprocess.run(cmd, check=True)


def docker_image_exists(tag: str) -> bool:
    try:
        subprocess.run(
            ["docker", "image", "inspect", tag],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True
    except Exception:
        return False


def build_local_image(tag: str, context_dir: pathlib.Path) -> bool:
    log(f"Building local Docker image '{tag}' from {context_dir}")
    try:
        subprocess.run(
            ["docker", "build", "-t", tag, str(context_dir)],
            check=True,
        )
        return True
    except Exception as exc:
        log(f"Local image build failed: {exc}")
        return False


def resolve_analysis_image(
    default_image: str,
    use_local_image: bool,
    local_image_tag: str,
    build_if_missing: bool,
    require_local_image: bool,
    repo_root: pathlib.Path,
) -> str:
    if not use_local_image:
        return default_image

    if docker_image_exists(local_image_tag):
        log(f"Using local image: {local_image_tag}")
        return local_image_tag

    if build_if_missing:
        built = build_local_image(local_image_tag, repo_root)
        if built and docker_image_exists(local_image_tag):
            log(f"Using newly built local image: {local_image_tag}")
            return local_image_tag

    if require_local_image:
        raise RuntimeError(
            f"Requested local image '{local_image_tag}', but it is unavailable. "
            "Build it first or remove --require-local-image."
        )

    log(f"Local image '{local_image_tag}' not available; falling back to {default_image}")
    return default_image


def check_ok(name: str, ok: bool, detail: str) -> tuple[str, bool, str]:
    return (name, ok, detail)


def run_testflight(
    image: str,
    binary_path: pathlib.Path | None,
    ghidra_text_start_raw: str | None,
    local_rules_dir: pathlib.Path,
) -> list[tuple[str, bool, str]]:
    checks: list[tuple[str, bool, str]] = []

    pyver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    checks.append(check_ok("python", True, pyver))

    docker_path = shutil.which("docker")
    checks.append(check_ok("docker_cli", docker_path is not None, docker_path or "not found in PATH"))

    if docker_path:
      try:
          subprocess.run(["docker", "info"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
          checks.append(check_ok("docker_daemon", True, "reachable"))
      except Exception:
          checks.append(check_ok("docker_daemon", False, "not reachable (is Docker running?)"))

      try:
          subprocess.run(["docker", "image", "inspect", image], check=True,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
          checks.append(check_ok("docker_image", True, image))
      except Exception:
          checks.append(check_ok("docker_image", False, f"not present locally: {image}"))

    readelf_tool = pick_readelf_tool()
    checks.append(check_ok("readelf", readelf_tool is not None, readelf_tool or "readelf/llvm-readelf not found"))

    checks.append(check_ok("local_rules", local_rules_dir.exists(), str(local_rules_dir)))

    if binary_path is not None:
        exists = binary_path.exists()
        checks.append(check_ok("binary_exists", exists, str(binary_path)))
        if exists:
            try:
                text_va = read_elf_text_vaddr(binary_path)
                checks.append(check_ok("binary_elf", True, f".text=0x{text_va:x}"))
            except Exception as exc:
                checks.append(check_ok("binary_elf", False, str(exc)))

    if ghidra_text_start_raw:
        try:
            val = resolve_ghidra_text_start(ghidra_text_start_raw)
            checks.append(check_ok("ghidra_text_input", True, f"0x{val:x}"))
        except Exception as exc:
            checks.append(check_ok("ghidra_text_input", False, str(exc)))

    return checks


def print_testflight(checks: list[tuple[str, bool, str]]) -> bool:
    print("\n=== Testflight ===")
    all_ok = True
    for name, ok, detail in checks:
        status = "OK" if ok else "FAIL"
        print(f"{name:16} {status:4} {detail}")
        if not ok:
            all_ok = False
    if all_ok:
        print("Testflight result: PASS")
    else:
        print("Testflight result: FAIL (see checks above)")
    return all_ok


def pick_readelf_tool() -> str | None:
    for name in ("readelf", "llvm-readelf", "greadelf"):
        tool = shutil.which(name)
        if tool:
            return tool
    return None


def probe_rtti(repo_root: pathlib.Path, binary_path: pathlib.Path) -> dict:
    probe_script = repo_root / "check_elf_rtti.py"
    if not probe_script.exists():
        return {"ok": False, "reason": f"missing probe script: {probe_script}"}

    proc = subprocess.run(
        ["python3", str(probe_script), "--json", str(binary_path)],
        text=True,
        capture_output=True,
    )
    if proc.returncode != 0:
        return {
            "ok": False,
            "reason": "RTTI probe failed",
            "stderr": proc.stderr.strip(),
            "stdout": proc.stdout.strip(),
        }

    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {
            "ok": False,
            "reason": "RTTI probe output was not valid JSON",
            "stdout": proc.stdout.strip(),
        }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run OOAnalyzer for ELF x64 and emit Ghidra-rebased JSON"
    )
    parser.add_argument("--binary", help="Path to ELF binary")
    parser.add_argument("--ghidra-text-start", help="Ghidra .text start VA (e.g. 0x1035a0)")
    parser.add_argument(
        "--ghidra-map-line",
        help="Raw Ghidra memory map line for .text (script extracts start address)",
    )
    parser.add_argument("--image", default="seipharos/pharos:latest", help="Docker image")
    parser.add_argument("--use-local-image", action="store_true",
                        help="Prefer a locally built image for analysis")
    parser.add_argument("--local-image-tag", default="pharos-local:latest",
                        help="Tag name for local analysis image")
    parser.add_argument("--build-local-image", action="store_true",
                        help="Build local image from repo Dockerfile when missing")
    parser.add_argument("--require-local-image", action="store_true",
                        help="Fail if local image is unavailable (no fallback)")
    parser.add_argument("--platform", help="Docker platform (e.g. linux/amd64)")
    parser.add_argument("--no-local-rules", action="store_true", help="Do not mount local oorules")
    parser.add_argument("--output-dir", help="Directory for outputs (default: binary directory)")
    parser.add_argument("--extra-arg", action="append", default=[], help="Extra ooanalyzer arg")
    parser.add_argument("--testflight", action="store_true", help="Run preflight health checks")
    parser.add_argument("--testflight-only", action="store_true", help="Run checks and exit")
    args = parser.parse_args()

    repo_root = pathlib.Path(__file__).resolve().parent
    local_rules_dir = repo_root / "share" / "prolog" / "oorules"

    selected_image = resolve_analysis_image(
        default_image=args.image,
        use_local_image=args.use_local_image,
        local_image_tag=args.local_image_tag,
        build_if_missing=args.build_local_image,
        require_local_image=args.require_local_image,
        repo_root=repo_root,
    )

    binary_path_for_checks = None
    if args.binary:
        binary_path_for_checks = pathlib.Path(args.binary).expanduser().resolve()
    ghidra_raw_for_checks = args.ghidra_text_start or args.ghidra_map_line

    if args.testflight or args.testflight_only:
        checks = run_testflight(selected_image, binary_path_for_checks, ghidra_raw_for_checks, local_rules_dir)
        ok = print_testflight(checks)
        if args.testflight_only:
            return 0 if ok else 1
        if not ok:
            raise RuntimeError("Testflight failed; aborting analysis. Fix failed checks or run --testflight-only to inspect.")

    binary_raw = prompt_if_missing(args.binary, "Binary path: ")
    ghidra_raw = args.ghidra_text_start or args.ghidra_map_line
    ghidra_raw = prompt_if_missing(
        ghidra_raw,
        "Ghidra .text start (hex) or full memory-map line: ",
    )

    binary_path = pathlib.Path(binary_raw).expanduser().resolve()
    if not binary_path.exists():
        raise FileNotFoundError(f"Binary does not exist: {binary_path}")

    ghidra_text_start = resolve_ghidra_text_start(ghidra_raw)
    output_dir = pathlib.Path(args.output_dir).expanduser().resolve() if args.output_dir else binary_path.parent
    output_dir.mkdir(parents=True, exist_ok=True)

    stem = binary_path.name
    json_path = output_dir / f"{stem}.json"
    facts_path = output_dir / f"{stem}.facts.pl"
    results_path = output_dir / f"{stem}.results.pl"
    ghidra_json_path = output_dir / f"{stem}.ghidra.json"

    input_mount = "/input"
    output_mount = "/output"
    container_binary = f"{input_mount}/{binary_path.name}"

    cmd = ["docker", "run", "--rm"]
    if args.platform:
        cmd += ["--platform", args.platform]
    cmd += [
        "-v", f"{binary_path.parent}:{input_mount}",
        "-v", f"{output_dir}:{output_mount}",
    ]
    if not args.no_local_rules and local_rules_dir.exists():
        cmd += ["-v", f"{local_rules_dir}:/usr/local/share/pharos/prolog/oorules"]
    cmd += [
        selected_image,
        "ooanalyzer",
        "--option", "pharos.allow_non_pe=true",
        "--allow-64bit",
        "--json", f"{output_mount}/{json_path.name}",
        "--prolog-facts", f"{output_mount}/{facts_path.name}",
        "--prolog-results", f"{output_mount}/{results_path.name}",
    ]
    for extra in args.extra_arg:
        cmd.append(extra)
    cmd.append(container_binary)

    log("Step 1/4: Probing RTTI symbols")
    rtti = probe_rtti(repo_root, binary_path)

    log("Step 2/4: Running OOAnalyzer in Docker")
    run_command(cmd)

    log("Step 3/4: Rebasing JSON to Ghidra load addresses")
    elf_text_start = read_elf_text_vaddr(binary_path)
    bias = ghidra_text_start - elf_text_start
    doc = json.loads(json_path.read_text())
    rebased = rebase_json(doc, bias)
    ghidra_json_path.write_text(json.dumps(rebased, indent=2, sort_keys=True) + "\n")

    log("Step 4/4: Reporting summary")
    summary = summarize(rebased)
    print("\n=== Output Files ===")
    print(f"Container image:   {selected_image}")
    print(f"Binary:            {binary_path}")
    print(f"JSON:              {json_path}")
    print(f"Ghidra JSON:       {ghidra_json_path}")
    print(f"Prolog facts:      {facts_path}")
    print(f"Prolog results:    {results_path}")

    print("\n=== Address Rebase ===")
    print(f"ELF .text start:   0x{elf_text_start:x}")
    print(f"Ghidra .text:      0x{ghidra_text_start:x}")
    print(f"Applied bias:      {bias:+#x}")

    print("\n=== RTTI Probe ===")
    if not rtti.get("ok"):
        print("Status:            unavailable")
        print(f"Reason:            {rtti.get('reason', 'unknown')}")
    else:
        print(f"Status:            {'likely present' if rtti.get('has_rtti') else 'not obvious'}")
        counts = rtti.get("counts", {})
        print(f"_ZTI/_ZTV/_ZTS:    {counts.get('_ZTI', 0)}/{counts.get('_ZTV', 0)}/{counts.get('_ZTS', 0)}")
        print(
            "Demangled RTTI:    "
            f"typeinfo={counts.get('demangled_typeinfo', 0)} "
            f"vtable={counts.get('demangled_vtable', 0)}"
        )
        print(f"Probe score:       {rtti.get('score', 0)}")

    print("\n=== JSON Summary ===")
    print(f"Classes:           {summary['class_count']}")
    print(f"Methods:           {summary['method_count']}")
    print(f"VFTables:          {summary['vftable_count']}")
    print(f"VFTable entries:   {summary['vft_entry_count']}")
    print(f"Virtual calls:     {summary['vcall_count']}")

    if summary["class_count"] == 0:
        print("\nQuality note: No classes were recovered. Check rules/load-bias and binary type.")
    elif summary["method_count"] <= summary["class_count"]:
        print("\nQuality note: Sparse methods per class; likely partial recovery on stripped ELF.")
    else:
        print("\nQuality note: Class recovery looks non-empty; inspect classes in Ghidra import logs.")

    if rtti.get("ok") and not rtti.get("has_rtti"):
        print("Quality note: RTTI probe did not find strong symbols; expect reduced class naming fidelity.")

    structures = rebased.get("structures", {})
    first_classes = list(structures.keys())[:3]
    print("\n=== Next Steps ===")
    print(f"Import JSON in Kaiju: {ghidra_json_path}")
    if first_classes:
        print("Check imported class names (first few): " + ", ".join(first_classes))
    print("If import appears unchanged, verify Ghidra .text start and rerun with that exact value.")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        raise SystemExit(130)
    except Exception as exc:  # pylint: disable=broad-except
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
