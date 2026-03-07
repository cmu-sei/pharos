#!/usr/bin/env python3
import argparse
import json
import pathlib
import re
import struct
import sys


HEX_ADDR_RE = re.compile(r"^0x[0-9a-fA-F]+$")
CLASS_ADDR_RE = re.compile(r"^cls_0x([0-9a-fA-F]+)$")


def parse_int(value: str) -> int:
    return int(value, 0)


def parse_ghidra_map_line(line: str) -> int:
    tokens = line.strip().split()
    if len(tokens) < 2:
        raise ValueError("Memory map line does not contain a start address")
    return int(tokens[1], 16)


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
    e_shoff = eh[6] if ei_class == 2 else eh[6]
    e_shentsize = eh[11] if ei_class == 2 else eh[11]
    e_shnum = eh[12] if ei_class == 2 else eh[12]
    e_shstrndx = eh[13] if ei_class == 2 else eh[13]

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
    if ei_class == 1:
        shstr_off, shstr_size = shstr[4], shstr[5]
    else:
        shstr_off, shstr_size = shstr[4], shstr[5]
    shstrtab = data[shstr_off:shstr_off + shstr_size]

    def read_cstr(blob: bytes, start: int) -> str:
        end = blob.find(b"\x00", start)
        if end == -1:
            end = len(blob)
        return blob[start:end].decode("utf-8", errors="replace")

    for sh in section_headers:
        sh_name = sh[0]
        name = read_cstr(shstrtab, sh_name)
        if name == ".text":
            if ei_class == 1:
                return sh[3]
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
            mname = CLASS_ADDR_RE.match(name)
            if mname:
                raw = int(mname.group(1), 16)
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


def derive_bias(args: argparse.Namespace) -> int:
    if args.bias is not None:
        return parse_int(args.bias)

    ghidra_text_start = None
    if args.ghidra_text_start is not None:
        ghidra_text_start = parse_int(args.ghidra_text_start)
    elif args.ghidra_map_line is not None:
        ghidra_text_start = parse_ghidra_map_line(args.ghidra_map_line)

    if ghidra_text_start is None:
        raise ValueError("Provide --bias, or provide --ghidra-text-start/--ghidra-map-line with --binary")
    if args.binary is None:
        raise ValueError("--binary is required when deriving bias from .text addresses")

    text_start = read_elf_text_vaddr(pathlib.Path(args.binary))
    return ghidra_text_start - text_start


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Rebase OOAnalyzer JSON addresses to match a Ghidra image base/load bias"
    )
    parser.add_argument("--json", required=True, help="Input OOAnalyzer JSON path")
    parser.add_argument("--output", help="Output JSON path (default: <input>.ghidra.json)")
    parser.add_argument("--in-place", action="store_true", help="Overwrite input JSON")
    parser.add_argument("--binary", help="ELF binary path (used to read .text section VA)")
    parser.add_argument("--bias", help="Address bias to add (e.g. 0x100000)")
    parser.add_argument("--ghidra-text-start", help="Ghidra .text start VA (e.g. 0x1035a0)")
    parser.add_argument("--ghidra-map-line", help="Raw Ghidra memory-map .text line")
    args = parser.parse_args()

    in_path = pathlib.Path(args.json)
    if not in_path.exists():
        raise FileNotFoundError(f"Input JSON not found: {in_path}")

    if args.in_place and args.output:
        raise ValueError("Use either --in-place or --output, not both")

    bias = derive_bias(args)

    out_path: pathlib.Path
    if args.in_place:
        out_path = in_path
    elif args.output:
        out_path = pathlib.Path(args.output)
    else:
        out_path = in_path.with_suffix("")
        out_path = pathlib.Path(str(out_path) + ".ghidra.json")

    doc = json.loads(in_path.read_text())
    rebased = rebase_json(doc, bias)
    out_path.write_text(json.dumps(rebased, indent=2, sort_keys=True) + "\n")

    print(f"Input JSON:        {in_path}")
    print(f"Output JSON:       {out_path}")
    print(f"Applied bias:      {bias:+#x}")
    if args.binary and (args.ghidra_text_start or args.ghidra_map_line):
        text_start = read_elf_text_vaddr(pathlib.Path(args.binary))
        print(f"ELF .text start:   0x{text_start:x}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # pylint: disable=broad-except
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
