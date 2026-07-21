# Vulnerability Localization Benchmark Dataset

## Dataset Summary

Vulnerability Localization Benchmark is an agentic benchmark for repository-scale vulnerability localization. Given a vulnerability description and a code repository, models are provided read-only terminal access to the repository and are evaluated on their ability to correctly localize the vulnerable file(s) or code path.

Unlike static code understanding benchmarks, Vulnerability Localization Benchmark measures end-to-end localization performance in a realistic repository exploration setting using terminal-based interactions.

The benchmark contains **500 real-world vulnerabilities** across 6 programming ecosystems (npm, pip, maven, go, rust, composer), constructed entirely from publicly available data. Each task includes:
- A vulnerable repository snapshot (`pre_push.zip`)
- A patched repository snapshot (`post_push.zip`) 
- Ground truth vulnerable files modified by the security patch
- Vulnerability metadata (GHSA ID, CVE, CWE, severity, description)

## Supported Tasks and Leaderboards

**Primary Task**: Agentic vulnerability localization in real-world codebases

**Evaluation Metrics**:
- File-level F1 score (precision/recall on vulnerable files)
- True Negative Rate (correctly identifying no vulnerability in patched code)

**Use Cases**:
- Evaluating code understanding capabilities of language models
- Testing agentic exploration and reasoning over large codebases
- Benchmarking security-focused AI systems
- Research in automated vulnerability detection

## Languages

The dataset includes vulnerabilities across multiple programming languages:
- **JavaScript** (npm ecosystem)
- **Python** (pip ecosystem)
- **Java** (maven ecosystem)
- **Go** (go ecosystem)
- **Rust** (rust ecosystem)
- **PHP** (composer ecosystem)

Vulnerability descriptions and metadata are in English.

## Dataset Structure

### Data Instances

Each entry in `manifest.csv` represents one vulnerability case with 26 fields:

```python
{
  "alpha_id": "0bCRIkhJ",
  "repo_full_name": "AhmedAdelFahim/express-xss-sanitizer",
  "ecosystem": "npm",
  "language": "JavaScript",
  "severity": "medium",
  "cvss_score": "5.3",
  "cwes": ["CWE-674"],
  "cwe_description": ["CWE-674: Uncontrolled Recursion..."],
  "ghsa_description": "# Security Advisory: express-xss-sanitizer...",
  "ground_truth_files": ["src/sanitizer.js"],
  "n_ground_truth_files": 1,
  "merge_commit_sha": "abc123...",
  "vulnerable_commit_sha": "def456...",
  "ghsa_id": "GHSA-xxxx-xxxx-xxxx",
  "cves": ["CVE-2023-12345"],
  "pr_url": "https://github.com/.../pull/123",
  "year": "2023",
  "vulnerable_LICENSE": "MIT",
  "merge_LICENSE": "MIT",
  ...
}
```

### Data Fields

**Core Identifiers:**
- `alpha_id`: Unique identifier for the vulnerability case
- `repo_full_name`: GitHub repository (owner/repo)
- `ghsa_id`: GitHub Security Advisory ID
- `cves`: Associated CVE identifier(s)

**Vulnerability Metadata:**
- `severity`: critical, high, medium, or low
- `cvss_score`: Common Vulnerability Scoring System score
- `cwes`: List of Common Weakness Enumeration IDs
- `cwe_description`: Human-readable CWE descriptions
- `ghsa_description`: Full vulnerability description from GHSA

**Repository Information:**
- `ecosystem`: Package ecosystem (npm, pip, maven, go, rust, composer)
- `language`: Primary programming language
- `vulnerable_commit_sha`: Git commit with the vulnerability
- `merge_commit_sha`: Git commit after the fix is merged
- `pr_url`: Link to the security patch pull request
- `year`: Year the vulnerability was disclosed

**Ground Truth:**
- `ground_truth_files`: List of vulnerable files (excludes tests/non-code)
- `n_ground_truth_files`: Count of vulnerable files

**Licensing:**
- `vulnerable_LICENSE`: License at vulnerable commit
- `merge_LICENSE`: License at patched commit

**File Metadata:**
- `vulnerable_zip_md5`: MD5 checksum for pre_push.zip
- `merge_zip_md5`: MD5 checksum for post_push.zip
- `vulnerable_zip_kb`: Compressed size of vulnerable repo
- `merge_zip_kb`: Compressed size of patched repo
- `vulnerable_unzip_kb`: Uncompressed size of vulnerable repo
- `merge_unzip_kb`: Uncompressed size of patched repo

**Additional Fields:**
- `notes`: Optional notes about the vulnerability case (e.g., special handling, known issues)

### Data Splits

The dataset contains a single evaluation split:
- **Test**: 500 vulnerability cases

The largest and most challenging repositories were held out from training data during curation and used exclusively for evaluation.

## Dataset Creation

### Source Data

#### Initial Data Collection

The benchmark is built entirely from publicly available data sources:

1. **GitHub Security Advisory Database (GHSA)**: Vulnerability metadata including descriptions, CVE/CWE identifiers, severity ratings, and CVSS scores
   - Source: https://github.com/advisories
   - All GHSA data is publicly accessible

2. **Open Source Repositories**: Snapshots of repositories at vulnerable and patched commits
   - 500 repositories sourced from GitHub
   - Each repository retains its original open source license
   - Complete license information available in `manifest.csv`

#### Who are the source data producers?

- **Vulnerability Metadata**: GitHub Security Advisory Database, maintained by GitHub and security researchers
- **Repository Code**: Open source maintainers and contributors
- **Ground Truth Labels**: Derived from security patch commits (files modified in the fix)

### Annotations

#### Annotation process

Ground truth vulnerable files are automatically extracted from security patch commits by identifying files modified between the vulnerable and patched states. Test files and non-code files are excluded from ground truth.

#### Who are the annotators?

Annotations are derived programmatically from git diffs. The original security patches were authored by repository maintainers and security researchers.

### Personal and Sensitive Information

The dataset contains only source code from public repositories. No personal or sensitive information is intentionally included. Users should be aware that public code repositories may occasionally contain accidentally committed credentials or personal data.

## Considerations for Using the Data

### Social Impact of Dataset

**Intended Use**: This benchmark enables evaluation of AI systems for security vulnerability detection and localization, which can help improve software security tooling.

**Potential Misuse**: Models trained on this data should not be used as the sole basis for security decisions. Automated vulnerability detection should always be verified by human security experts.

### Discussion of Biases

- **Language Bias**: Dataset includes vulnerabilities from 6 ecosystems, but coverage is not uniform across all programming languages
- **Repository Size Bias**: Larger, more popular repositories may be overrepresented
- **Temporal Bias**: Vulnerabilities span 2016-2026, with potential evolution in vulnerability types over time
- **Severity Bias**: High and medium severity vulnerabilities are more common than critical or low

### Other Known Limitations

- **Historical Snapshots**: Vulnerability information reflects the state at dataset creation time
- **Ground Truth Scope**: Ground truth only includes files modified in the security patch; some vulnerabilities may span additional files
- **Repository Access**: Some source repositories may become unavailable over time (archived in `deleted-repo-mirrors/`)

## Additional Information

### Dataset Curators

Vulnerability Localization Benchmark was created by Cisco Foundation AI.

### Licensing Information

**Benchmark Framework**: Apache License 2.0

**Dataset Content**: The benchmark dataset uses public vulnerability data and open source repositories that retain their original licenses.

**License Distribution of Included Repositories:**
- Apache-2.0: 241 repositories (48.2%)
- MIT: 161 repositories (32.2%)
- Other: 46 repositories (9.2%)
- GPL-3.0: 15 repositories (3.0%)
- LGPL: 12 repositories (2.4%)
- MPL-2.0: 12 repositories (2.4%)
- BSD-3-Clause: 5 repositories (1.0%)
- Creative Commons: 4 repositories (0.8%)
- ISC: 2 repositories (0.4%)
- GPL-2.0: 1 repository (0.2%)
- AGPL-3.0: 1 repository (0.2%)

**Important**: All repository content is subject to the original repository's license terms. Users must comply with each included repository's license. See the NOTICE file for complete attribution requirements.

### Citation Information

```bibtex
@misc{vulnlocalizationbench2026,
  title={Vulnerability Localization Benchmark: An Agentic Benchmark for Repository-Scale Vulnerability Localization},
  author={Cisco Foundation AI},
  year={2026},
  url={https://github.com/cisco-foundation-ai/vulnerability-localization-benchmark}
}
```

### Contributions

We acknowledge and thank:
- Security researchers who discovered and responsibly disclosed these vulnerabilities
- The GitHub team for maintaining the Security Advisory Database
- All open source maintainers whose repositories are included in this benchmark

For questions about data sources, attribution, or licensing, please open an issue at https://github.com/cisco-foundation-ai/vulnerability-localization-benchmark.

## Dataset Statistics

### Severity Distribution

| Severity | Count | Percentage |
|----------|-------|------------|
| High | 219 | 43.8% |
| Medium | 194 | 38.8% |
| Critical | 57 | 11.4% |
| Low | 30 | 6.0% |

### Top CWEs (147 unique)

| CWE | Description | Count |
|-----|-------------|-------|
| CWE-400 | Resource Exhaustion | 53 |
| CWE-20 | Improper Input Validation | 45 |
| CWE-200 | Information Exposure | 27 |
| CWE-22 | Path Traversal | 27 |
| CWE-770 | Allocation without Limits | 23 |

### Coverage

- **CVE Coverage**: 78% of entries have assigned CVE identifiers
- **Years Covered**: 2016-2026
- **Total Cases**: 500 vulnerability instances

### Safety Notice

⚠️ **Important**: This benchmark requires executing code in sandboxed Docker containers. Repository snapshots may contain vulnerable code. Always run evaluations in isolated environments with appropriate security controls.
