# Additive VLoc intake (v1)

The upstream repository is preserved byte-for-byte at
`fa50b671aa0b954d73691d6ef8d592d42a2ac1e0`; the root README, manifest,
code, LICENSE (Apache-2.0), and NOTICE remain unchanged. These additions do not
claim to be an upstream release. Target repositories retain their own licenses;
there is no blanket relicensing.

`tools/normalize_vloc_v1.py` is a standard-library-only, metadata-only normalizer.
It reads pinned Git objects, not mutable checkout files, and refuses existing
output directories. It never imports upstream apps, downloads all snapshots,
executes target code, installs dependencies, calls models, or runs containers.

```sh
python3 tools/normalize_vloc_v1.py --output-dir /tmp/vloc-new-output
python3 -m unittest discover -s tests_normalization -v
```

The generated authority is `datasets/vloc/{cases.jsonl,source.json,summary.json}`.
Every case includes the entire native manifest row on the evaluator side, its
1-based CSV data-row index, physical line range (advisories span lines), and
SHA-256 of canonical UTF-8 JSON of the original string-valued row. SHA-256 of
the original CSV proves its byte identity. CWE descriptions are preserved
verbatim; queries are never synthesized from advisory text, patch files, or
case labels. Empty and cardinality-mismatched native lists are not repaired.

Inventory: 500 task rows, 290 repositories, 411 distinct nonempty GHSA IDs,
347 CVEs, 439 native snapshot pairs, 437 vulnerable revisions, 439 fixed
revisions, and 2,618 patch-file labels. Empty GHSA is not a 412th advisory.
The denominator remains 500: tasks are not deduplicated into advisories.

499 tasks pin both revisions. `vloc-wyfFZf7k` (`minio/console`) has an empty
vulnerable SHA and an upstream `repo_deleted` mirror note. It is retained with
null vulnerable revision and `requires_mirror` status, not guessed or silently
excluded. 39 rows lack GHSA, 19 lack CWE descriptions, and 8 have differing
CWE-ID/description list lengths. Source acquisition, semantic review, training
readiness, candidate pools, and model evaluation are **not completed**.

The model-facing whitelist is native generic CWE descriptions plus a *single*
repository/commit source request. The harness must hide phase/pair identity and
all evaluator fields. Fixed revisions are provenance, not whole-repository
safe labels. The native file filter and exact-set F1/TNR do not establish
function/line correctness, mechanism correctness, or runtime confirmation.
An offline whole-repository code bank is a separate access protocol from the
official limited-terminal agent; no official benchmark score is claimed here.
