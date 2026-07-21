# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""
Extract 64 repo/model/vuln features from pre_push.zip files and manifest.csv.
Produces a feature matrix CSV for the regressor.

Usage:
    python repo_feature_extractor.py \
        --manifest /path/to/manifest.csv \
        --zips-dir /path/to/ghsa-vulns/ \
        --results-dir /path/to/benchmark-results/ \
        --output features.csv
"""

import argparse
import csv
import json
import math
import os
import zipfile
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

from tqdm import tqdm

SOURCE_EXTS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".rs", ".rb",
    ".php", ".c", ".cpp", ".h", ".hpp", ".cs", ".swift", ".kt", ".scala",
    ".sol", ".vue", ".svelte", ".zig", ".lua", ".pl", ".pm",
}
TEST_PATTERNS = {"test", "tests", "spec", "specs", "__tests__", "testing"}
CONFIG_EXTS = {".json", ".yaml", ".yml", ".toml", ".xml", ".ini", ".cfg"}
BUILD_FILES = {
    "makefile", "cmakelists.txt", "build.gradle", "build.gradle.kts",
    "pom.xml", "build.sbt", "cargo.toml", "package.json", "setup.py",
    "pyproject.toml", "meson.build", "justfile", "rakefile",
}
CI_PATHS = {".github/workflows", ".circleci", "jenkinsfile", ".travis.yml", ".gitlab-ci.yml"}
CWE_INPUT_VALIDATION = {"CWE-20", "CWE-22", "CWE-79", "CWE-89", "CWE-94", "CWE-77", "CWE-78"}
CWE_MEMORY = {"CWE-121", "CWE-122", "CWE-125", "CWE-401", "CWE-416", "CWE-787"}
CWE_RESOURCE = {"CWE-400", "CWE-770", "CWE-409", "CWE-834", "CWE-674"}

MODEL_SIZES = {
    "gpt-5.5_xhigh": 1000, "gpt-5.5": 1000, "gpt-5": 1500,
    "gpt-5-mini": 200, "gpt-5-nano": 50, "gpt-4o-mini": 70,
    "gpt-oss-120B": 120, "gpt-oss-20B": 20,
    "gemini-3-pro-preview": 500, "gemini-2.5-flash": 300,
    "gemini-3.1-flash-lite-preview": 100,
    "gemma-4-31B": 31, "gemma-4-26B-A4B": 26,
    "gemma-4-E4B": 4, "gemma-4-E2B": 2,
    "Qwen3.5-122B-A10B": 122, "Qwen3.5-35B-A3B": 35,
    "Qwen3.5-27B": 27, "Qwen3.5-9B": 9, "Qwen3.5-4B": 4, "Qwen3.5-0.8B": 0.8,
    "deepseek-v4-flash": 236, "DS-R1-Qwen-7B": 7,
    "Llama-3.3-70B": 70, "minimax-m2.7": 456,
    "CodeScout-14B": 14, "CodeScout-1.7B": 1.7, "CodeScout-1.7B-RFT": 1.7,
    "Nanbeige4.1-3B": 3, "Primus-Reasoning": 70,
    "FoundSec-Instruct": 7, "GLM-4.7-Flash": 9,
    "Antares-3B-GRPO": 3, "Antares-3B-SFT": 3,
    "Antares-H-3B-SFT": 3, "Antares-1B-SFT": 1,
    "Antares-H-1B-SFT": 1, "Antares-350M-SFT": 0.35,
    "Antares-H-350M-SFT": 0.35,
}

MOE_MODELS = {"Qwen3.5-122B-A10B", "Qwen3.5-35B-A3B", "gemma-4-26B-A4B", "deepseek-v4-flash", "minimax-m2.7"}

MODEL_FAMILIES = {
    "gpt-5.5_xhigh": "gpt", "gpt-5.5": "gpt", "gpt-5": "gpt",
    "gpt-5-mini": "gpt", "gpt-5-nano": "gpt", "gpt-4o-mini": "gpt",
    "gpt-oss-120B": "gpt", "gpt-oss-20B": "gpt",
    "gemini-3-pro-preview": "gemini", "gemini-2.5-flash": "gemini",
    "gemini-3.1-flash-lite-preview": "gemini",
    "gemma-4-31B": "gemma", "gemma-4-26B-A4B": "gemma",
    "gemma-4-E4B": "gemma", "gemma-4-E2B": "gemma",
    "Qwen3.5-122B-A10B": "qwen", "Qwen3.5-35B-A3B": "qwen",
    "Qwen3.5-27B": "qwen", "Qwen3.5-9B": "qwen",
    "Qwen3.5-4B": "qwen", "Qwen3.5-0.8B": "qwen",
    "deepseek-v4-flash": "deepseek", "DS-R1-Qwen-7B": "deepseek",
    "Llama-3.3-70B": "llama", "minimax-m2.7": "minimax",
    "CodeScout-14B": "codescout", "CodeScout-1.7B": "codescout",
    "CodeScout-1.7B-RFT": "codescout",
    "Nanbeige4.1-3B": "other", "Primus-Reasoning": "other",
    "FoundSec-Instruct": "other", "GLM-4.7-Flash": "other",
    "Antares-3B-GRPO": "antares", "Antares-3B-SFT": "antares",
    "Antares-H-3B-SFT": "antares", "Antares-1B-SFT": "antares",
    "Antares-H-1B-SFT": "antares", "Antares-350M-SFT": "antares",
    "Antares-H-350M-SFT": "antares",
}

ALL_FAMILIES = ["gpt", "gemini", "gemma", "qwen", "deepseek", "llama", "minimax", "codescout", "antares", "other"]
ALL_ECOSYSTEMS = ["npm", "pip", "go", "rust", "maven", "composer"]
ALL_SEVERITIES = ["critical", "high", "medium", "low"]


def safe_log10(x):
    return math.log10(max(x, 1))


def shannon_entropy(counts):
    total = sum(counts.values())
    if total == 0:
        return 0.0
    probs = [c / total for c in counts.values() if c > 0]
    return -sum(p * math.log2(p) for p in probs)


def extract_repo_features(zip_path):
    """Extract structural features from a pre_push.zip file."""
    features = {}

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            names = zf.namelist()
    except (zipfile.BadZipFile, FileNotFoundError):
        return None

    # Filter to files only (not dirs)
    files = [n for n in names if not n.endswith("/")]
    dirs = set()
    for f in files:
        parts = Path(f).parts
        for i in range(1, len(parts)):
            dirs.add("/".join(parts[:i]))

    # Source files
    source_files = [f for f in files if Path(f).suffix.lower() in SOURCE_EXTS]

    # LOC per source file
    file_locs = []
    comment_lines = 0
    total_lines = 0
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            for sf in source_files[:500]:  # cap at 500 files for speed
                try:
                    data = zf.read(sf)
                    lines = data.decode("utf-8", errors="ignore").split("\n")
                    loc = len(lines)
                    file_locs.append(loc)
                    total_lines += loc
                    for line in lines:
                        stripped = line.strip()
                        if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("*") or stripped.startswith("/*"):
                            comment_lines += 1
                except:
                    pass
    except:
        pass

    if not file_locs:
        file_locs = [0]

    # Depths
    file_depths = []
    for f in source_files:
        file_depths.append(len(Path(f).parts) - 1)
    if not file_depths:
        file_depths = [0]

    # Extensions distribution
    ext_counts = Counter(Path(f).suffix.lower() for f in source_files if Path(f).suffix)

    # Test detection
    test_files = [f for f in files if any(tp in f.lower() for tp in TEST_PATTERNS)]
    test_locs = []
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            for tf in test_files[:100]:
                try:
                    data = zf.read(tf)
                    test_locs.append(len(data.decode("utf-8", errors="ignore").split("\n")))
                except:
                    pass
    except:
        pass

    # Config files in root-ish
    root_configs = [f for f in files if Path(f).suffix.lower() in CONFIG_EXTS and len(Path(f).parts) <= 2]

    # Build scripts
    build_scripts = [f for f in files if Path(f).name.lower() in BUILD_FILES]

    # CI detection
    has_ci = any(any(ci in f.lower() for ci in CI_PATHS) for f in files)

    # Docker detection
    has_docker = any("dockerfile" in Path(f).name.lower() for f in files)

    # README
    has_readme = any("readme" in Path(f).name.lower() for f in files)

    # Dotfiles
    dotfiles = [f for f in files if Path(f).name.startswith(".") and len(Path(f).parts) <= 2]

    # Dependencies count (heuristic: look for package.json, requirements.txt, go.sum, Cargo.toml)
    n_deps = 0
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            for f in files:
                fname = Path(f).name.lower()
                if fname == "package.json" and len(Path(f).parts) <= 2:
                    try:
                        pkg = json.loads(zf.read(f))
                        n_deps += len(pkg.get("dependencies", {})) + len(pkg.get("devDependencies", {}))
                    except:
                        pass
                elif fname == "requirements.txt" and len(Path(f).parts) <= 2:
                    try:
                        n_deps += len([l for l in zf.read(f).decode("utf-8", errors="ignore").split("\n") if l.strip() and not l.startswith("#")])
                    except:
                        pass
                elif fname == "go.sum" and len(Path(f).parts) <= 2:
                    try:
                        n_deps += len(zf.read(f).decode("utf-8", errors="ignore").split("\n")) // 2
                    except:
                        pass
    except:
        pass

    # Languages
    lang_exts = Counter(Path(f).suffix.lower() for f in source_files)
    n_languages = len([e for e, c in lang_exts.items() if c >= 3])

    # Directory fanout
    dir_file_counts = Counter()
    for f in source_files:
        parent = str(Path(f).parent)
        dir_file_counts[parent] += 1

    sorted_locs = sorted(file_locs, reverse=True)
    top5_loc = sum(sorted_locs[:5])

    # --- Assign features ---
    features["source_file_count"] = len(source_files)
    features["total_source_loc"] = sum(file_locs)
    features["avg_file_loc"] = sum(file_locs) / len(file_locs) if file_locs else 0
    features["max_file_loc"] = max(file_locs) if file_locs else 0
    features["median_file_loc"] = sorted(file_locs)[len(file_locs) // 2] if file_locs else 0
    features["top5_loc_share"] = top5_loc / max(sum(file_locs), 1)
    features["pct_large_files"] = len([l for l in file_locs if l > 500]) / max(len(file_locs), 1)
    features["directory_depth"] = max(file_depths)
    features["avg_directory_depth"] = sum(file_depths) / len(file_depths) if file_depths else 0
    features["depth_p90"] = sorted(file_depths)[int(len(file_depths) * 0.9)] if file_depths else 0
    features["depth_std"] = (sum((d - features["avg_directory_depth"])**2 for d in file_depths) / max(len(file_depths), 1)) ** 0.5
    features["n_dirs_depth_3plus"] = len([d for d in file_depths if d >= 3])
    features["pct_files_depth_1"] = len([d for d in file_depths if d <= 1]) / max(len(file_depths), 1)
    features["n_directories"] = len(dirs)
    features["file_ext_entropy"] = shannon_entropy(ext_counts)
    features["max_directory_fanout"] = max(dir_file_counts.values()) if dir_file_counts else 0
    features["test_to_source_file_ratio"] = len(test_files) / max(len(source_files), 1)
    features["pct_test_loc"] = sum(test_locs) / max(total_lines, 1)
    features["n_languages"] = max(n_languages, 1)
    features["comment_line_ratio"] = comment_lines / max(total_lines, 1)
    features["has_readme"] = 1.0 if has_readme else 0.0
    features["has_tests_dir"] = 1.0 if test_files else 0.0
    features["has_ci"] = 1.0 if has_ci else 0.0
    features["has_docker"] = 1.0 if has_docker else 0.0
    features["n_config_files"] = len(root_configs)
    features["n_dependencies"] = n_deps
    features["n_build_scripts"] = len(build_scripts)
    features["n_dotfiles"] = len(dotfiles)

    return features


def extract_manifest_features(row):
    """Extract features derivable from manifest.csv columns."""
    features = {}

    vuln_kb = float(row.get("vulnerable_unzip_kb", 0) or 0)
    zip_kb = float(row.get("vulnerable_zip_kb", 0) or 0)
    merge_kb = float(row.get("merge_unzip_kb", 0) or 0)

    features["log10_repo_size_kb"] = safe_log10(vuln_kb)
    features["log10_zip_size_kb"] = safe_log10(zip_kb)
    features["log10_merge_size_kb"] = safe_log10(merge_kb)
    features["compression_ratio"] = vuln_kb / max(zip_kb, 1)
    features["size_delta_pct"] = (merge_kb - vuln_kb) / max(vuln_kb, 1)

    # Repo size bucket (ordinal 1-6)
    if vuln_kb < 100:
        features["repo_size_bucket"] = 1
    elif vuln_kb < 500:
        features["repo_size_bucket"] = 2
    elif vuln_kb < 2000:
        features["repo_size_bucket"] = 3
    elif vuln_kb < 10000:
        features["repo_size_bucket"] = 4
    elif vuln_kb < 50000:
        features["repo_size_bucket"] = 5
    else:
        features["repo_size_bucket"] = 6

    # Vulnerability features
    cvss_raw = row.get("cvss_score", "7.0")
    try:
        features["cvss_score"] = float(cvss_raw)
    except (ValueError, TypeError):
        features["cvss_score"] = 7.0
    ngt_raw = row.get("n_ground_truth_files", "1")
    try:
        features["n_gt_files"] = int(float(ngt_raw))
    except (ValueError, TypeError):
        features["n_gt_files"] = 1
    year_raw = row.get("year", "2023")
    try:
        features["year"] = int(float(year_raw))
    except (ValueError, TypeError):
        features["year"] = 2023

    cwes_raw = row.get("cwes", "[]")
    try:
        cwes = json.loads(cwes_raw) if isinstance(cwes_raw, str) else cwes_raw
    except:
        cwes = []
    features["n_cwes"] = len(cwes) if cwes else 0

    cves_raw = row.get("cves", "[]")
    try:
        cves = json.loads(cves_raw) if isinstance(cves_raw, str) else cves_raw
    except:
        cves = []
    features["n_cves"] = len(cves) if cves else 0

    cwe_set = set(cwes) if cwes else set()
    features["cwe_input_validation"] = 1.0 if cwe_set & CWE_INPUT_VALIDATION else 0.0
    features["cwe_memory"] = 1.0 if cwe_set & CWE_MEMORY else 0.0
    features["cwe_resource"] = 1.0 if cwe_set & CWE_RESOURCE else 0.0

    # Ecosystem one-hot
    eco = row.get("ecosystem", "")
    for e in ALL_ECOSYSTEMS:
        features[f"ecosystem_{e}"] = 1.0 if eco == e else 0.0

    # Severity one-hot
    sev = row.get("severity", "")
    for s in ALL_SEVERITIES:
        features[f"severity_{s}"] = 1.0 if sev == s else 0.0

    return features


def extract_model_features(model_name):
    """Extract model features."""
    features = {}
    size_b = MODEL_SIZES.get(model_name, 5)
    features["log10_model_params"] = safe_log10(size_b)
    features["is_moe"] = 1.0 if model_name in MOE_MODELS else 0.0

    family = MODEL_FAMILIES.get(model_name, "other")
    for f in ALL_FAMILIES:
        features[f"family_{f}"] = 1.0 if family == f else 0.0

    return features


def _extract_worker(alpha_id, zip_path):
    if os.path.exists(zip_path):
        feats = extract_repo_features(zip_path)
        if feats:
            return alpha_id, feats
    return alpha_id, None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--zips-dir", required=True)
    parser.add_argument("--results-dir", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    # Load manifest
    with open(args.manifest) as f:
        reader = csv.DictReader(f)
        manifest = {row["alpha_id"]: row for row in reader}

    print(f"Manifest: {len(manifest)} entries")

    # Extract repo features (cached per alpha_id) — 64 workers
    repo_cache = {}
    zips_dir = args.zips_dir
    tasks = [(aid, os.path.join(zips_dir, aid, "pre_push.zip")) for aid in manifest]

    with ProcessPoolExecutor(max_workers=64) as executor:
        futures = {executor.submit(_extract_worker, aid, zp): aid for aid, zp in tasks}
        for future in tqdm(as_completed(futures), total=len(futures), desc="Extracting repo features"):
            aid, feats = future.result()
            if feats:
                repo_cache[aid] = feats

    print(f"Extracted repo features for {len(repo_cache)} entries")

    # Load all phase_a results
    results = []
    for model_dir in sorted(os.listdir(args.results_dir)):
        model_path = os.path.join(args.results_dir, model_dir)
        if not os.path.isdir(model_path):
            continue
        for fname in os.listdir(model_path):
            if not fname.endswith("_phase_a.json"):
                continue
            alpha_id = fname.replace("_phase_a.json", "")
            fpath = os.path.join(model_path, fname)
            try:
                with open(fpath) as f:
                    d = json.load(f)
                results.append({
                    "alpha_id": alpha_id,
                    "model": model_dir,
                    "file_f1": d.get("file_f1", 0.0),
                })
            except:
                pass

    print(f"Loaded {len(results)} eval results across {len(set(r['model'] for r in results))} models")

    # Build feature matrix
    rows_out = []
    feature_names = None
    for r in results:
        alpha_id = r["alpha_id"]
        if alpha_id not in manifest or alpha_id not in repo_cache:
            continue

        manifest_feats = extract_manifest_features(manifest[alpha_id])
        repo_feats = repo_cache[alpha_id]
        model_feats = extract_model_features(r["model"])

        row = {}
        row.update(repo_feats)
        row.update(manifest_feats)
        row.update(model_feats)
        row["file_f1"] = r["file_f1"]
        row["alpha_id"] = alpha_id
        row["model"] = r["model"]

        if feature_names is None:
            feature_names = sorted([k for k in row.keys() if k not in ("file_f1", "alpha_id", "model")])

        rows_out.append(row)

    print(f"Feature matrix: {len(rows_out)} rows × {len(feature_names)} features")

    # Write CSV
    with open(args.output, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["alpha_id", "model"] + feature_names + ["file_f1"])
        writer.writeheader()
        for row in rows_out:
            writer.writerow({k: row.get(k, 0) for k in writer.fieldnames})

    print(f"Written to {args.output}")


if __name__ == "__main__":
    main()
