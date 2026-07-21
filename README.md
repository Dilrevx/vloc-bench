# Vulnerability Localization Benchmark

[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.1-fbab2c.svg)](CODE_OF_CONDUCT.md)
[![Maintainer](https://img.shields.io/badge/Maintainer-Cisco-00bceb.svg)](https://opensource.cisco.com)

## About The Project

Vulnerability Localization Benchmark is an agentic benchmark for evaluating AI models on repository-scale vulnerability localization. Given a vulnerability description and read-only terminal access to a codebase, models must explore the repository and identify which files contain security vulnerabilities.

**Key Features:**
- 500 real-world vulnerabilities from public GitHub Security Advisories
- Two-phase evaluation: Phase A (find vulnerabilities) and Phase B (confirm fixes)
- Multi-ecosystem coverage: npm, pip, maven, go, rust, composer
- Docker-sandboxed evaluation environment
- Reproducible with MD5-verified dataset

Unlike static code understanding benchmarks, Vulnerability Localization Benchmark measures end-to-end localization performance in realistic repository exploration settings using terminal-based interactions.

📄 **Technical Report** (coming soon) | arXiv (coming soon)

## Getting Started

### Prerequisites

- Python 3.11 or higher
- Docker (for sandboxed evaluation)
- A model server supporting OpenAI-compatible API (e.g., vLLM)

```bash
# Verify Python version
python3 --version

# Verify Docker installation
docker --version
```

### Installation

1. Clone the repository

   ```bash
   git clone https://github.com/cisco-foundation-ai/vulnerability-localization-benchmark.git
   cd vulnerability-localization-benchmark
   ```

2. Install the package

   ```bash
   pip install -e .
   ```

3. Build the sandbox Docker image

   ```bash
   docker build -t vulnerability-localization-benchmark-sandbox .
   ```

4. Download and verify the dataset

   ```bash
   python data/downloader_and_verifier.py --source-dir /path/to/dataset/
   ```

   This downloads all 500 repository pairs into `data/ghsa-vulns/{alpha_id}/` and verifies MD5 checksums.

## Usage

### Running Evaluations

1. Start your model server (example with vLLM):

   ```bash
   CUDA_VISIBLE_DEVICES=0 python -m vllm.entrypoints.openai.api_server \
       --model /path/to/model \
       --served-model-name your-model \
       --host 0.0.0.0 --port 8200 \
       --dtype bfloat16 --gpu-memory-utilization 0.9 \
       --max-model-len 32768 --tensor-parallel-size 1 \
       --trust-remote-code
   ```

2. Run Phase A evaluation (vulnerable codebases):

   ```bash
   PYTHONPATH=src python3 -m vulnerability_localization_benchmark.cli \
       --config configs/default.yaml \
       --api-base http://localhost:8200/v1 \
       --model-name your-model \
       --runner vllm \
       --output-dir results/my-run \
       --phases a \
       --workers 16
   ```

3. Run Phase B evaluation (patched codebases):

   ```bash
   PYTHONPATH=src python3 -m vulnerability_localization_benchmark.cli \
       --config configs/default.yaml \
       --api-base http://localhost:8200/v1 \
       --model-name your-model \
       --runner vllm \
       --output-dir results/my-run \
       --phases b \
       --workers 16
   ```

### Evaluation Protocol

**Phase A (pre_push):** Model explores vulnerable codebase with terminal access (15 tool call budget), then submits files it believes contain the vulnerability. Scored on File F1 against ground truth.

**Phase B (post_push):** Model explores patched codebase under same protocol. Should declare "no vulnerability found". Scored on True Negative Rate.

### Dataset

500 real-world vulnerabilities across 6 ecosystems. 78% have assigned CVEs.

| Severity | Count | CWE Types | Ecosystems |
|----------|-------|-----------|------------|
| High | 219 | 147 unique | npm, pip, maven, go, rust, composer |
| Medium | 194 |
| Critical | 57 |
| Low | 30 |

📄 See [DATASET_CARD.md](DATASET_CARD.md) for detailed dataset documentation including data fields, biases, statistics, and licensing.

#### Example Vulnerabilities

**Critical: Signature Bypass ([CVE-2024-32962](https://nvd.nist.gov/vuln/detail/CVE-2024-32962))**
- **Repository**: node-saml/xml-crypto (npm/JavaScript)
- **CWE-347**: Improper Verification of Cryptographic Signature
- **Ground Truth**: `src/signed-xml.ts` (single file)
- **Challenge**: Default configuration doesn't check signer authorization, only signature validity

**Medium: Mutex Unsoundness**
- **Repository**: Amanieu/parking_lot (rust)
- **CWE-362**: Concurrent Execution using Shared Resource with Improper Synchronization
- **Ground Truth**: `lock_api/src/lib.rs`, `lock_api/src/mutex.rs`, `lock_api/src/rwlock.rs` (3 files)
- **Challenge**: Data race in lock implementation affecting multiple synchronization primitives

#### Dataset Statistics

**Severity Distribution:**

| Severity | Count |
|----------|-------|
| High | 219 |
| Medium | 194 |
| Critical | 57 |
| Low | 30 |

**Top CWEs (147 unique):**

| CWE | Count |
|-----|-------|
| CWE-400 (Resource Exhaustion) | 53 |
| CWE-20 (Improper Input Validation) | 45 |
| CWE-200 (Information Exposure) | 27 |
| CWE-22 (Path Traversal) | 27 |
| CWE-770 (Allocation without Limits) | 23 |

**Top Repositories:**

| Repository | Count |
|-----------|-------|
| mmaitre314/picklescan | 21 |
| undertow-io/undertow | 14 |
| kubernetes/kubernetes | 11 |
| vyperlang/vyper | 10 |
| keycloak/keycloak | 10 |

**License Distribution:**

| License | Count | Percentage |
|---------|-------|------------|
| Apache-2.0 | 241 | 48.2% |
| MIT | 161 | 32.2% |
| Other | 46 | 9.2% |
| GPL-3.0 | 15 | 3.0% |
| LGPL | 12 | 2.4% |
| MPL-2.0 | 12 | 2.4% |
| BSD-3-Clause | 5 | 1.0% |
| Creative Commons | 4 | 0.8% |
| ISC | 2 | 0.4% |
| GPL-2.0 | 1 | 0.2% |
| AGPL-3.0 | 1 | 0.2% |

All repositories retain their original open source licenses. No license changes between vulnerable and patched states. The "Other" category includes dual-licensed crates and less common licenses (e.g., MIT OR Apache-2.0, EPL-2.0, BSD-2-Clause). See `data/manifest.csv` for license information per repository, and the `NOTICE` file for complete attribution requirements.

*Note: License data verified via ScanCode and GitHub Licensee tools. Some entries have dual licenses (e.g., EPL-2.0 OR Apache-2.0) where either option may be used.*

**Each entry provides:**
- `pre_push.zip` — repository at the vulnerable commit (Phase A input)
- `post_push.zip` — repository after the fix is merged (Phase B input)
- `ground_truth_files` — code files modified by the security patch (excludes tests and non-code files)
- `cwe_description` — generic CWE definition (used in eval prompt)

### CLI Options

| Flag | Description |
|------|-------------|
| `--config` | YAML config path (default: `configs/default.yaml`) |
| `--api-base` | Model endpoint URL |
| `--model-name` | Model name as served by vLLM |
| `--runner` | `vllm_antares` / `vllm` / `vllm_qwen_3_5` / `vllm_gemma_4` |
| `--output-dir` | Where to write results + traces |
| `--phases` | `a`, `b`, or `ab` |
| `--n-limit` | Max entries to evaluate (0 = all) |
| `--workers` | Parallel workers (default 1) |
| `--resume` | Skip entries with existing results |
| `--permissive` | Disable command validation (sandbox is isolated) |

### Model Runners

| Runner | Endpoint | Use Case |
|--------|----------|----------|
| `vllm` | `/v1/chat/completions` | Generic models with native tool calling |
| `vllm_antares` | `/v1/completions` | Antares models with built-in reasoning |
| `vllm_qwen_3_5` | `/v1/chat/completions` | Qwen 3.5 with tool parser |
| `vllm_gemma_4` | `/v1/chat/completions` | Gemma 4 with tool parser |

For more examples and advanced usage, see the [full documentation](https://github.com/cisco-foundation-ai/vulnerability-localization-benchmark/wiki).

### Output Format

Per entry, two files are written to `--output-dir`:
- `{alpha_id}_phase_{a|b}.json` — scores, metadata, submitted files
- `{alpha_id}_phase_{a|b}_trace.json` — full conversation trace

Final aggregate scores are saved to `aggregate.json`.

### Agent Behavior

- 15 terminal calls budget per entry
- Up to 20 turns total (generation cycles)
- If model emits 3 consecutive turns with no tool call → forced stop
- If terminal budget exhausted → nudge to submit
- frequency_penalty=0.3 prevents repetition loops
- `--permissive` skips command validation (recommended — container is sandboxed)
- Docker container build: mean 0.41s, median 0.30s, max 1.0s

### Key Parameters

From `configs/default.yaml`:

| Parameter | Value | Why |
|-----------|-------|-----|
| max_tokens | 16384 | Per-turn generation cap |
| max_turns | 20 | Agent loop budget |
| terminal_calls | 15 | Per-entry budget |

### Antares-Specific Configuration

For `vllm_antares` runner:

| Parameter | Value | Why |
|-----------|-------|-----|
| Endpoint | `/v1/completions` | Raw text, NOT chat API |
| temperature | 0.3 | Low variance for eval |
| frequency_penalty | 0.3 | Prevent repetition loops |
| stop tokens | `<\|end_of_text\|>`, `<\|start_of_role\|>` | Antares special tokens |
| Generation prefix | `<think>\n` | Triggers reasoning mode |

Other runners (Qwen, Gemma) use `/v1/chat/completions` — vLLM handles template formatting via `--tool-call-parser`. The Antares runner uses `/v1/completions` with its own template and built-in reasoning via `<think>` prefix.

### Repository Structure

```
├── pyproject.toml                    # pip-installable (hatchling)
├── Dockerfile                        # vulnerability-localization-benchmark-sandbox image (ubuntu:24.04)
├── configs/default.yaml              # All tunable params
├── data/
│   ├── manifest.csv                  # 500 entries, 26 columns
│   ├── downloader_and_verifier.py    # Downloads + MD5-verifies all zips
│   ├── deleted-repo-mirrors/         # Zips for repos no longer on GitHub
│   │   └── GHSA-4999-659w-mq36/     # pre_push.zip, post_push.zip
│   └── ghsa-vulns/                   # [gitignored] downloaded zips
│       └── {alpha_id}/
│           ├── pre_push.zip          # Vulnerable codebase (Phase A)
│           └── post_push.zip         # Patched codebase (Phase B)
├── src/vulnerability_localization_benchmark/
│   ├── __init__.py
│   ├── cli.py                        # Entrypoint, orchestrate workers
│   ├── agent.py                      # Agent loop (runner-agnostic)
│   ├── sandbox.py                    # Docker container per entry
│   ├── scoring.py                    # File F1, TNR, aggregation
│   └── model_runners/
│       ├── base.py                   # Shared system prompt + tools schema
│       ├── vllm.py                   # Generic vLLM /v1/chat/completions
│       ├── vllm_antares.py           # Antares: raw /v1/completions
│       ├── vllm_qwen_3_5.py          # Qwen 3.5: tool calling
│       └── vllm_gemma_4.py           # Gemma 4: tool calling
└── results/                          # [gitignored] eval output
```

### Website

GitHub Pages leaderboard served from `docs/`:

```
docs/
├── index.html              # Interactive single-page leaderboard (all CSS/JS inline)
└── model-performance.json  # Eval results data
```

## Leaderboard Participation

We welcome submissions of new model results to the [public leaderboard](https://cisco-foundation-ai.github.io/vulnerability-localization-benchmark/). To add your model:

1. **Evaluate your model** on the benchmark by following the [evaluation instructions](#usage) above. This produces a per-model results file.
2. **Fork** this repository.
3. **Add your model's entry** to `docs/model-performance.json`. Each entry follows this schema:

   ```json
   {
     "model": "Your-Model-Name",
     "type": "frontier",              // "frontier" or "open-weights"
     "size": "7B",                    // parameter count; "—" for closed frontier models
     "file_f1": 0.123,                // Phase A: File F1 (0–1)
     "precision": 0.234,
     "recall": 0.201,
     "true_negative_rate": 0.567,     // Phase B (optional)
     "false_positive_rate": 0.089,
     "submitted_nothing_rate": 0.145
   }
   ```

4. **Open a pull request** with your added entry and a short description of your evaluation setup (model version, harness, date).

### ✅ Result Verification

To keep the leaderboard trustworthy, submissions should include enough detail to reproduce the run:

- The exact model identifier / version and inference settings (temperature, reasoning effort, etc.).
- The harness used (this repo's CLI, or a documented equivalent).
- Raw evaluation output (attach to the PR or link to it) so maintainers can spot-check the reported metrics.

Maintainers may request the raw prediction logs before merging. Once verified, your model appears on the live leaderboard.

## Roadmap

See the [open issues](https://github.com/cisco-foundation-ai/vulnerability-localization-benchmark/issues) for proposed features and known issues.

## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**. For detailed contributing guidelines, please see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Distributed under the Apache License 2.0. See [LICENSE](LICENSE) for more information.

**Dataset Licensing:** The benchmark dataset uses public vulnerability data and open source repositories that retain their original licenses. See [NOTICE](NOTICE) for attribution and license compliance requirements.

## Contact

Cisco Foundation AI - [GitHub](https://github.com/cisco-foundation-ai)

Project Link: [https://github.com/cisco-foundation-ai/vulnerability-localization-benchmark](https://github.com/cisco-foundation-ai/vulnerability-localization-benchmark)

For questions about data sources, attribution, or licensing, please open an [issue](https://github.com/cisco-foundation-ai/vulnerability-localization-benchmark/issues).

## Acknowledgements

- Security researchers who discovered and responsibly disclosed these vulnerabilities
- The GitHub team for maintaining the Security Advisory Database
- All open source maintainers whose repositories are included in this benchmark
