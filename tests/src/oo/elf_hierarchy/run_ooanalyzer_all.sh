#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${SCRIPT_DIR}/out"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../../.." && pwd)"
LOCAL_OORULES_DIR="${REPO_ROOT}/share/prolog/oorules"
JSON_REBASE_TOOL="${REPO_ROOT}/tools/ooanalyzer/rebase_json_for_ghidra.py"
IMAGE="${PHAROS_IMAGE:-seipharos/pharos:latest}"
PLATFORM="${PHAROS_PLATFORM:-}"
GHIDRA_TEXT_START="${GHIDRA_TEXT_START:-}"
EXTRA_ARGS=()
DOCKER_PLATFORM_ARGS=()
DOCKER_MOUNT_ARGS=()
DRY_RUN=0

usage() {
  cat <<'EOF'
Usage:
  ./run_ooanalyzer_all.sh [--dry-run] [--ghidra-text-start HEX] [--extra-arg ARG]...

Description:
  Runs OOAnalyzer against all generated ELF variants and writes outputs side-by-side.

Inputs (must exist in ./out):
  - pipeline_dwarf
  - pipeline_stripped
  - pipeline_split

Outputs:
  - pipeline_dwarf.json / .facts.pl / .results.pl
  - pipeline_stripped.json / .facts.pl / .results.pl
  - pipeline_split.json / .facts.pl / .results.pl

Environment variables:
  PHAROS_IMAGE     Docker image (default: seipharos/pharos:latest)
  PHAROS_PLATFORM  Optional docker platform (example: linux/amd64)
  PHAROS_USE_LOCAL_RULES  Mount repo oorules into container (default: 1)
  GHIDRA_TEXT_START  Optional .text start VA from Ghidra (example: 0x1035a0)

Examples:
  ./run_ooanalyzer_all.sh
  PHAROS_PLATFORM=linux/amd64 ./run_ooanalyzer_all.sh
  ./run_ooanalyzer_all.sh --ghidra-text-start 0x1035a0
  ./run_ooanalyzer_all.sh --extra-arg --threads=8
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --extra-arg)
      if [[ $# -lt 2 ]]; then
        echo "error: --extra-arg requires a value" >&2
        exit 2
      fi
      EXTRA_ARGS+=("$2")
      shift 2
      ;;
    --ghidra-text-start)
      if [[ $# -lt 2 ]]; then
        echo "error: --ghidra-text-start requires a value" >&2
        exit 2
      fi
      GHIDRA_TEXT_START="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ ! -d "${OUT_DIR}" ]]; then
  echo "error: missing output directory: ${OUT_DIR}" >&2
  echo "hint: run ./build_linux_elf.sh first" >&2
  exit 1
fi

for bin in pipeline_dwarf pipeline_stripped pipeline_split; do
  if [[ ! -f "${OUT_DIR}/${bin}" ]]; then
    echo "error: missing binary: ${OUT_DIR}/${bin}" >&2
    echo "hint: run ./build_linux_elf.sh first" >&2
    exit 1
  fi
done

if [[ -n "${PLATFORM}" ]]; then
  DOCKER_PLATFORM_ARGS=(--platform "${PLATFORM}")
fi

if [[ "${PHAROS_USE_LOCAL_RULES:-1}" != "0" ]]; then
  if [[ -d "${LOCAL_OORULES_DIR}" ]]; then
    DOCKER_MOUNT_ARGS+=(
      -v "${LOCAL_OORULES_DIR}:/usr/local/share/pharos/prolog/oorules"
    )
  else
    echo "warning: local oorules directory not found: ${LOCAL_OORULES_DIR}" >&2
  fi
fi

run_case() {
  local stem="$1"
  local cmd=(docker run --rm)
  if [[ ${#DOCKER_PLATFORM_ARGS[@]} -gt 0 ]]; then
    cmd+=("${DOCKER_PLATFORM_ARGS[@]}")
  fi
  cmd+=(
    -v "${OUT_DIR}:/work"
    "${DOCKER_MOUNT_ARGS[@]}"
    "${IMAGE}"
    ooanalyzer
    --option pharos.allow_non_pe=true
    --allow-64bit
    --json "/work/${stem}.json"
    --prolog-facts "/work/${stem}.facts.pl"
    --prolog-results "/work/${stem}.results.pl"
  )
  if [[ ${#EXTRA_ARGS[@]} -gt 0 ]]; then
    cmd+=("${EXTRA_ARGS[@]}")
  fi
  cmd+=("/work/${stem}")

  echo "[+] Running ${stem}"
  if [[ ${DRY_RUN} -eq 1 ]]; then
    printf '    %q ' "${cmd[@]}"
    printf '\n'
  else
    "${cmd[@]}"

    if [[ -n "${GHIDRA_TEXT_START}" ]]; then
      if [[ ! -f "${JSON_REBASE_TOOL}" ]]; then
        echo "warning: missing rebase tool: ${JSON_REBASE_TOOL}" >&2
      else
        local in_json="${OUT_DIR}/${stem}.json"
        local out_json="${OUT_DIR}/${stem}.ghidra.json"
        local bin_path="${OUT_DIR}/${stem}"
        python3 "${JSON_REBASE_TOOL}" \
          --json "${in_json}" \
          --binary "${bin_path}" \
          --ghidra-text-start "${GHIDRA_TEXT_START}" \
          --output "${out_json}"
      fi
    fi
  fi
}

run_case pipeline_dwarf
run_case pipeline_stripped
run_case pipeline_split

if [[ ${DRY_RUN} -eq 0 ]]; then
  echo "[+] Complete. Outputs written under ${OUT_DIR}"
fi
