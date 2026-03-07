#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="${SCRIPT_DIR}/three_level_pipeline.cpp"
OUT_DIR="${SCRIPT_DIR}/out"

mkdir -p "${OUT_DIR}"

docker run --rm \
  --platform linux/amd64 \
  -v "${SCRIPT_DIR}:/src" \
  ubuntu:24.04 \
  bash -lc '
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive
    apt-get update >/dev/null
    apt-get install -y --no-install-recommends g++ binutils >/dev/null

    g++ -std=c++20 -O2 -fno-omit-frame-pointer -g3 -gdwarf-5 \
      -fno-inline -fno-optimize-sibling-calls -pthread \
      /src/three_level_pipeline.cpp -o /src/out/pipeline_dwarf

    cp /src/out/pipeline_dwarf /src/out/pipeline_stripped
    strip --strip-all /src/out/pipeline_stripped

    cp /src/out/pipeline_dwarf /src/out/pipeline_split
    objcopy --only-keep-debug /src/out/pipeline_split /src/out/pipeline_split.debug
    objcopy --strip-debug /src/out/pipeline_split
    objcopy --add-gnu-debuglink=/src/out/pipeline_split.debug /src/out/pipeline_split

    readelf -h /src/out/pipeline_dwarf >/dev/null
    readelf -h /src/out/pipeline_stripped >/dev/null
    readelf -h /src/out/pipeline_split >/dev/null
  '

echo "Artifacts written to: ${OUT_DIR}"
