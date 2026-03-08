# OO Matrix Benchmark

This directory includes a single-source benchmark for measuring OOAnalyzer behavior across
architecture, format, RTTI, and strip settings.

## Benchmark source

- `oo_matrix10.cpp`
  - 10 classes
  - mixed inheritance (including multiple/virtual inheritance)
  - 4-6 methods per class
  - polymorphic dispatch exercised in `main()`

## Run full matrix

From repo root:

```bash
./tests/src/oo/run_oo_matrix.sh
```

Matrix dimensions:

- format: ELF, PE
- bits: x86, x64
- RTTI: on, off
- strip: debug, stripped

## Outputs

- binaries: `tests/src/oo/oo_matrix_out/bin`
- ooanalyzer logs/json/facts/results: `tests/src/oo/oo_matrix_out/analysis`
- summary CSV: `tests/src/oo/oo_matrix_out/report/summary.csv`
- aggregate accuracy report: `tests/src/oo/oo_matrix_out/report/accuracy_report.txt`

## Accuracy metric

The benchmark has 10 known classes. The report estimates:

- class recall
- class precision
- class F1

using recovered class count from OOAnalyzer logs.
