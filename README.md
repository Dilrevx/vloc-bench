# VLoc Benchmark

500 native file-localization tasks, with 2,618 primary file labels. The original [Cisco Foundation AI benchmark](https://github.com/cisco-foundation-ai/vulnerability-localization-benchmark) uses phase-A File F1 and phase-B true-negative rate; repository-search recall is a separate protocol.

## Data

- [`dataset/cases.jsonl`](dataset/cases.jsonl): the shared `bench-dataset-v1` records: identity/group, split, origin, language, identifiers, source versions, labels, patches, runtime references and provenance.
- [`dataset/manifest.json`](dataset/manifest.json): counts, original file receipts, asset hashes, modes and license associations.
- `dataset/assets/`: byte-preserved source/evidence/oracle/knowledge/license assets, indexed by the manifest. Answer-bearing data are not model inputs.

Original files remain available at [the fixed pre-migration commit](https://github.com/Dilrevx/vloc-bench/tree/5aefc553424c0509b5244f7e03db22b129189ca1). Original records and meaningful annotations are translated into the common cases, not used as an alternative runtime format. Models, experiments and results belong in [embed](https://github.com/Dilrevx/embed).

## Use

Use embed's [`benchmarks/vloc/dataset-lock.json`](https://github.com/Dilrevx/embed/blob/spec-audit-ab/benchmarks/vloc/dataset-lock.json) and [common runner](https://github.com/Dilrevx/embed/blob/spec-audit-ab/docs/method-runner.md). From the embed checkout:

```sh
PYTHONPATH=src python -m embedbench validate-dataset \
  --benchmark-checkout ../vloc-bench \
  --lock benchmarks/vloc/dataset-lock.json
```

Validation checks all cases, references, asset bytes and file modes without executing targets. Labels are location/assessment evidence, not proof of exploitation; a fixed version is not a blanket safe-repository label. Missing original version bindings remain explicitly recorded.

## Rights

Original attribution and licensing boundaries are retained in the root legal files and `manifest.license`; nested legal texts are byte-preserved assets with their original scopes. No blanket relicensing of third-party target code or data is asserted.
