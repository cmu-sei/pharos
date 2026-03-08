#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SRC="${ROOT_DIR}/tests/src/oo/oo_matrix10.cpp"
OUT_DIR="${ROOT_DIR}/tests/src/oo/oo_matrix_out"
BIN_DIR="${OUT_DIR}/bin"
ANALYSIS_DIR="${OUT_DIR}/analysis"
REPORT_DIR="${OUT_DIR}/report"
BUILD_IMAGE="${BUILD_IMAGE:-ubuntu:24.04}"
ANALYZE_IMAGE="${ANALYZE_IMAGE:-seipharos/pharos:latest}"
MOUNT_LOCAL_RULES="${MOUNT_LOCAL_RULES:-1}"

mkdir -p "${BIN_DIR}" "${ANALYSIS_DIR}" "${REPORT_DIR}"

echo "[1/4] Building matrix binaries"
docker run --rm --platform linux/amd64 \
  -v "${ROOT_DIR}:/src" \
  "${BUILD_IMAGE}" \
  bash -lc '
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive
    apt-get update >/dev/null
    apt-get install -y --no-install-recommends g++ g++-multilib binutils mingw-w64 >/dev/null

    SRC=/src/tests/src/oo/oo_matrix10.cpp
    BIN=/src/tests/src/oo/oo_matrix_out/bin

    build_elf() {
      local bits="$1" rtti="$2" out="$3"
      local bitflag="-m64"
      if [[ "$bits" == "x86" ]]; then bitflag="-m32"; fi
      local rtti_flags=""
      if [[ "$rtti" == "off" ]]; then rtti_flags="-fno-rtti -DNO_RTTI_EXERCISE"; fi
      g++ -std=c++17 -O2 -fno-inline -fno-optimize-sibling-calls -fno-omit-frame-pointer \
        ${bitflag} ${rtti_flags} "${SRC}" -o "${BIN}/${out}"
    }

    build_pe() {
      local bits="$1" rtti="$2" out="$3"
      local cxx="x86_64-w64-mingw32-g++"
      if [[ "$bits" == "x86" ]]; then cxx="i686-w64-mingw32-g++"; fi
      local rtti_flags=""
      if [[ "$rtti" == "off" ]]; then rtti_flags="-fno-rtti -DNO_RTTI_EXERCISE"; fi
      "${cxx}" -std=c++17 -O2 -fno-inline -fno-optimize-sibling-calls \
        ${rtti_flags} "${SRC}" -o "${BIN}/${out}"
    }

    for fmt in elf pe; do
      for bits in x86 x64; do
        for rtti in on off; do
          stem="oo_matrix10_${fmt}_${bits}_rtti_${rtti}"
          if [[ "$fmt" == "elf" ]]; then
            build_elf "$bits" "$rtti" "${stem}_dbg"
            cp "${BIN}/${stem}_dbg" "${BIN}/${stem}_stripped"
            strip --strip-all "${BIN}/${stem}_stripped"
          else
            build_pe "$bits" "$rtti" "${stem}_dbg.exe"
            cp "${BIN}/${stem}_dbg.exe" "${BIN}/${stem}_stripped.exe"
            if [[ "$bits" == "x64" ]]; then
              x86_64-w64-mingw32-strip --strip-all "${BIN}/${stem}_stripped.exe"
            else
              i686-w64-mingw32-strip --strip-all "${BIN}/${stem}_stripped.exe"
            fi
          fi
        done
      done
    done
  '

echo "[2/4] Running OOAnalyzer on all variants"
CSV="${REPORT_DIR}/summary.csv"
echo "variant,format,bits,rtti,stripped,classes,methods,vcalls,usage" > "${CSV}"

for file in "${BIN_DIR}"/*; do
  base="$(basename "${file}")"
  stem="${base%.*}"
  ext="${base##*.}"
  format="elf"
  if [[ "${ext}" == "exe" ]]; then format="pe"; fi

  bits="x64"
  [[ "${stem}" == *"_x86_"* ]] && bits="x86"
  rtti="on"
  [[ "${stem}" == *"_rtti_off"* ]] && rtti="off"
  stripped="no"
  [[ "${stem}" == *"_stripped"* ]] && stripped="yes"

  log="${ANALYSIS_DIR}/${stem}.log"
  json="${ANALYSIS_DIR}/${stem}.json"
  facts="${ANALYSIS_DIR}/${stem}.facts.pl"
  results="${ANALYSIS_DIR}/${stem}.results.pl"

  docker_args=(docker run --rm --platform linux/amd64 -v "${BIN_DIR}:/work/bin" -v "${ANALYSIS_DIR}:/work/out")
  if [[ "${MOUNT_LOCAL_RULES}" == "1" ]]; then
    docker_args+=( -v "${ROOT_DIR}/share/prolog/oorules:/usr/local/share/pharos/prolog/oorules" )
  fi
  docker_args+=("${ANALYZE_IMAGE}" ooanalyzer)

  if [[ "${format}" == "elf" ]]; then
    docker_args+=(--option pharos.allow_non_pe=true)
  fi
  if [[ "${bits}" == "x64" ]]; then
    docker_args+=(--allow-64bit)
  fi

  docker_args+=(--json "/work/out/${stem}.json" --prolog-facts "/work/out/${stem}.facts.pl" --prolog-results "/work/out/${stem}.results.pl" "/work/bin/${base}")

  echo "  - ${stem}"
  "${docker_args[@]}" > "${log}" 2>&1 || true

  line="$(rg "found: [0-9]+ classes, [0-9]+ methods, [0-9]+ virtual calls, and [0-9]+ usage instructions" "${log}" || true)"
  if [[ -z "${line}" ]]; then
    echo "${stem},${format},${bits},${rtti},${stripped},0,0,0,0" >> "${CSV}"
    continue
  fi

  classes="$(echo "${line}" | sed -E 's/.*found: ([0-9]+) classes.*/\1/')"
  methods="$(echo "${line}" | sed -E 's/.*classes, ([0-9]+) methods.*/\1/')"
  vcalls="$(echo "${line}" | sed -E 's/.*methods, ([0-9]+) virtual calls.*/\1/')"
  usage="$(echo "${line}" | sed -E 's/.*virtual calls, and ([0-9]+) usage instructions.*/\1/')"
  echo "${stem},${format},${bits},${rtti},${stripped},${classes},${methods},${vcalls},${usage}" >> "${CSV}"
done

echo "[3/4] Building merged 32/64 accuracy report"
REPORT_TXT="${REPORT_DIR}/accuracy_report.txt"
EXPECTED_CLASSES=10
awk -F, -v expected="${EXPECTED_CLASSES}" '
  NR==1 { next }
  {
    found=$6+0
    tp=found
    if (tp>expected) tp=expected
    recall=(expected>0)?(tp/expected):0
    precision=(found>0)?(tp/found):0
    f1=(precision+recall>0)?(2*precision*recall/(precision+recall)):0
    r=recall*100
    p=precision*100
    f=f1*100
    if ($3=="x86") { x86_sum+=f; x86_n+=1 }
    if ($3=="x64") { x64_sum+=f; x64_n+=1 }
    all_sum+=f; all_n+=1
    printf "%s | cls=%d meth=%d vcall=%d usage=%d | recall=%.1f%% precision=%.1f%% f1=%.1f%%\n", $1, $6, $7, $8, $9, r, p, f
  }
  END {
    printf "\nExpected classes: %d\n", expected
    if (x86_n>0) printf "x86 aggregate class F1: %.1f%% over %d runs\n", (x86_sum/x86_n), x86_n
    if (x64_n>0) printf "x64 aggregate class F1: %.1f%% over %d runs\n", (x64_sum/x64_n), x64_n
    if (all_n>0) printf "combined class F1: %.1f%% over %d runs\n", (all_sum/all_n), all_n
  }
' "${CSV}" > "${REPORT_TXT}"

echo "[4/4] Done"
echo "- Binaries: ${BIN_DIR}"
echo "- Analysis: ${ANALYSIS_DIR}"
echo "- CSV: ${CSV}"
echo "- Report: ${REPORT_TXT}"
