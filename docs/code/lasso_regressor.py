# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""
Run Lasso regression on extracted features → predict File F1.
Produces pred-score-eval-analytics.json for the website 3D chart.

Usage:
    python lasso_regressor.py \
        --features features.csv \
        --output ../pred-score-eval-analytics.json
"""

import argparse
import json
import math

import numpy as np
import pandas as pd
from sklearn.linear_model import LassoCV
from sklearn.model_selection import cross_val_score
from sklearn.preprocessing import StandardScaler

FEATURE_GROUPS = {
    "Repo Size": [
        "log10_repo_size_kb", "log10_zip_size_kb", "log10_merge_size_kb",
        "compression_ratio", "size_delta_pct", "repo_size_bucket",
    ],
    "Repo Structure": [
        "source_file_count", "total_source_loc", "avg_file_loc", "max_file_loc",
        "median_file_loc", "top5_loc_share", "pct_large_files",
        "directory_depth", "avg_directory_depth", "depth_p90", "depth_std",
        "n_dirs_depth_3plus", "pct_files_depth_1",
        "n_directories", "file_ext_entropy", "max_directory_fanout",
        "test_to_source_file_ratio", "pct_test_loc", "n_languages",
    ],
    "Repo Signals": [
        "comment_line_ratio", "has_readme", "has_tests_dir", "has_ci",
        "has_docker", "n_config_files", "n_dependencies",
        "n_build_scripts", "n_dotfiles",
    ],
    "Model": [
        "log10_model_params", "is_moe",
        "family_gpt", "family_gemini", "family_gemma", "family_qwen",
        "family_deepseek", "family_llama", "family_minimax",
        "family_codescout", "family_antares", "family_other",
    ],
    "Ecosystem": [
        "ecosystem_npm", "ecosystem_pip", "ecosystem_go",
        "ecosystem_rust", "ecosystem_maven", "ecosystem_composer",
    ],
    "Severity": [
        "severity_critical", "severity_high", "severity_medium", "severity_low",
    ],
    "Vulnerability": [
        "cvss_score", "n_gt_files", "n_cwes", "n_cves", "year",
        "cwe_input_validation", "cwe_memory", "cwe_resource",
    ],
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--features", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    df = pd.read_csv(args.features)
    print(f"Loaded {len(df)} rows")

    # Collect all feature columns (ordered by group)
    all_features = []
    for group_feats in FEATURE_GROUPS.values():
        for f in group_feats:
            if f in df.columns:
                all_features.append(f)
            else:
                print(f"  WARNING: feature '{f}' not in CSV, skipping")

    print(f"Using {len(all_features)} features")

    X = df[all_features].fillna(0).values.astype(np.float64)
    y = df["file_f1"].fillna(0).values.astype(np.float64)

    # Standardize
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # LassoCV
    alphas = np.logspace(-5, -1, 100)
    lasso = LassoCV(cv=5, alphas=alphas, random_state=42, max_iter=20000)
    lasso.fit(X_scaled, y)

    r2_train = lasso.score(X_scaled, y)
    cv_scores = cross_val_score(lasso, X_scaled, y, cv=5, scoring="r2")
    r2_cv = cv_scores.mean()
    r2_cv_std = cv_scores.std()

    print(f"R² train: {r2_train:.4f}")
    print(f"R² CV:    {r2_cv:.4f} ± {r2_cv_std:.4f}")
    print(f"Alpha:    {lasso.alpha_:.6f}")
    print(f"Nonzero:  {np.sum(lasso.coef_ != 0)}/{len(lasso.coef_)}")
    print(f"Intercept: {lasso.intercept_:.6f}")

    # Build feature details
    features_out = []
    for i, fname in enumerate(all_features):
        coef = float(lasso.coef_[i])
        col_vals = X[:, i]
        features_out.append({
            "feature": fname,
            "coef": round(coef, 6),
            "mean": round(float(scaler.mean_[i]), 4),
            "std": round(float(scaler.scale_[i]), 4),
            "raw_min": round(float(col_vals.min()), 4),
            "raw_max": round(float(col_vals.max()), 4),
            "p10": round(float(np.percentile(col_vals, 10)), 4),
            "p25": round(float(np.percentile(col_vals, 25)), 4),
            "p50": round(float(np.percentile(col_vals, 50)), 4),
            "p75": round(float(np.percentile(col_vals, 75)), 4),
            "p90": round(float(np.percentile(col_vals, 90)), 4),
        })

    # Group importance (sum of |coef| per group)
    grouped_importance = {}
    for group_name, group_feats in FEATURE_GROUPS.items():
        total = 0.0
        for f in group_feats:
            if f in all_features:
                idx = all_features.index(f)
                total += abs(lasso.coef_[idx])
        grouped_importance[group_name] = round(total, 5)

    # Top features sorted by |coef|
    top_features = sorted(
        [f for f in features_out if f["coef"] != 0],
        key=lambda x: -abs(x["coef"])
    )

    result = {
        "metadata": {
            "total_samples": int(len(y)),
            "n_models": int(df["model"].nunique()),
            "n_entries": int(df["alpha_id"].nunique()),
            "r2_train": round(r2_train, 4),
            "r2_cv": round(r2_cv, 4),
            "r2_cv_std": round(r2_cv_std, 4),
            "alpha": round(float(lasso.alpha_), 6),
            "intercept": round(float(lasso.intercept_), 6),
            "nonzero_features": int(np.sum(lasso.coef_ != 0)),
            "total_features": len(all_features),
            "mean_f1": round(float(y.mean()), 4),
            "std_f1": round(float(y.std()), 4),
        },
        "features": features_out,
        "top_features": top_features,
        "grouped_importance": grouped_importance,
    }

    with open(args.output, "w") as f:
        json.dump(result, f, indent=2)

    print(f"\nWritten to {args.output}")
    print(f"\nTop 10 features:")
    for tf in top_features[:10]:
        direction = "+" if tf["coef"] > 0 else "-"
        print(f"  {direction} {tf['feature']:30s} {tf['coef']:+.5f}")


if __name__ == "__main__":
    main()
