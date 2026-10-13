# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Scoring — File F1 + TNR."""

CODE_EXTS = {'.go', '.java', '.py', '.js', '.ts', '.jsx', '.tsx', '.rs', '.rb',
             '.php', '.c', '.cpp', '.h', '.hpp', '.cs', '.scala', '.kt', '.swift'}


def is_test_file(path: str) -> bool:
    p = path.lower()
    return ('test' in p or '_spec' in p or 'spec/' in p or '__tests__/' in p)


def filter_ground_truth(files: list[str]) -> list[str]:
    import os
    code = [f for f in files if os.path.splitext(f)[1].lower() in CODE_EXTS]
    return [f for f in code if not is_test_file(f)]


def file_f1(submitted: list[str], ground_truth: list[str]) -> dict:
    if not submitted and not ground_truth:
        return {"precision": 1.0, "recall": 1.0, "file_f1": 1.0}
    if not submitted or not ground_truth:
        return {"precision": 0.0, "recall": 0.0, "file_f1": 0.0}

    sub_set = set(submitted)
    gt_set = set(ground_truth)
    tp = len(sub_set & gt_set)

    precision = tp / len(sub_set) if sub_set else 0.0
    recall = tp / len(gt_set) if gt_set else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    return {"precision": round(precision, 4), "recall": round(recall, 4), "file_f1": round(f1, 4)}


def score_phase_a(submitted: list[str], ground_truth: list[str], submitted_nothing: bool) -> dict:
    if submitted_nothing:
        return {"file_f1": 0.0, "precision": 0.0, "recall": 0.0, "abstained": True}
    scores = file_f1(submitted, ground_truth)
    scores["abstained"] = False
    return scores


def score_phase_b(submitted: list[str], submitted_nothing: bool) -> dict:
    true_negative = submitted_nothing
    return {
        "true_negative": true_negative,
        "false_positive": not true_negative,
        "n_false_positive_files": len(submitted) if not true_negative else 0,
    }


def aggregate_scores(results: list[dict], phase: str) -> dict:
    if not results:
        return {}

    if phase == "a":
        f1s = [r["file_f1"] for r in results]
        abstains = [r.get("abstained", False) for r in results]
        return {
            "mean_file_f1": round(sum(f1s) / len(f1s), 4),
            "abstain_rate": round(sum(abstains) / len(abstains), 4),
            "n_entries": len(results),
        }
    elif phase == "b":
        tns = [r["true_negative"] for r in results]
        return {
            "true_negative_rate": round(sum(tns) / len(tns), 4),
            "false_positive_rate": round(1 - sum(tns) / len(tns), 4),
            "n_entries": len(results),
        }
    return {}
