#!/usr/bin/env python3
"""Normalize pinned VLoc metadata only; never execute upstream/target code.

Existing files, including all upstream files, are never overwritten. Rebuild to
a fresh directory and compare bytes to verify determinism.
"""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import subprocess

UPSTREAM = 'https://github.com/cisco-foundation-ai/vulnerability-localization-benchmark'
COMMIT = 'fa50b671aa0b954d73691d6ef8d592d42a2ac1e0'
VERSION = 'vloc-normalized-v1'
RAW = 'data/manifest.csv'
PROVENANCE = (RAW, 'LICENSE', 'NOTICE', 'README.md', 'DATASET_CARD.md',
              'data/downloader_and_verifier.py', 'configs/default.yaml',
              'src/vulnerability_localization_benchmark/scoring.py',
              'src/vulnerability_localization_benchmark/agent.py',
              'src/vulnerability_localization_benchmark/cli.py')
FIELDS = ('alpha_id', 'repo_full_name', 'ecosystem', 'language', 'severity', 'cvss_score',
          'cwes', 'cwe_description', 'ghsa_description', 'ground_truth_files',
          'n_ground_truth_files', 'merge_commit_sha', 'vulnerable_commit_sha', 'ghsa_id',
          'cves', 'pr_url', 'year', 'vulnerable_zip_md5', 'merge_zip_md5',
          'vulnerable_LICENSE', 'merge_LICENSE', 'vulnerable_zip_kb', 'merge_zip_kb',
          'vulnerable_unzip_kb', 'merge_unzip_kb', 'notes',
          'vulnerable_content_md5', 'merge_content_md5')
CODE_EXTS = {'.go', '.java', '.py', '.js', '.ts', '.jsx', '.tsx', '.rs', '.rb',
             '.php', '.c', '.cpp', '.h', '.hpp', '.cs', '.scala', '.kt', '.swift'}
PROTOCOL = dict(model_input='native_generic_cwe_descriptions_and_one_source_snapshot_only',
                evaluator_only=['advisory', 'CVE', 'ground_truth_files', 'patch',
                                'paired_revision', 'native_manifest_row', 'raw_ref'],
                official_metrics=['phase_a_file_f1', 'phase_b_true_negative_rate'],
                offline_bank_is_separate_protocol=True,
                labels='patch_derived_files_not_function_or_runtime_oracle',
                patched_snapshot_is_not_whole_repository_safe=True,
                target_code_executed=False, upstream_code_executed=False, model_called=False)
LICENSE = dict(upstream='Apache-2.0', license_path='LICENSE', notice_path='NOTICE',
               third_party_boundary='Target source licenses remain as in native manifest and repositories; no blanket relicensing.')


def require(value, message):
    if not value:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'),
                      allow_nan=False).encode('utf-8')


def pretty(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2,
                       allow_nan=False) + '\n').encode('utf-8')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def safe_path(value):
    require(isinstance(value, str) and value and '\\' not in value and '\x00' not in value,
            'Invalid VLoc relative path')
    path = PurePosixPath(value)
    require(not path.is_absolute() and '..' not in path.parts and bool(path.parts)
            and str(path) == value, 'Unsafe VLoc relative path')
    return value


def string_list(value, blank=False):
    if blank and value == '':
        return []
    result = json.loads(value)
    require(isinstance(result, list) and all(isinstance(item, str) and item
            and '\x00' not in item for item in result), 'Invalid VLoc JSON string list')
    return result


def filter_ground_truth(files):
    # Same extension and deliberately broad test-name filter as pinned scorer.
    return [path for path in files if PurePosixPath(path).suffix.lower() in CODE_EXTS
            and not any(part in path.lower() for part in ('test', '_spec', 'spec/', '__tests__/'))]


def read_rows(body):
    reader = csv.DictReader(io.StringIO(body.decode('utf-8'), newline=''), strict=True)
    require(tuple(reader.fieldnames or ()) == FIELDS, 'Unexpected VLoc manifest header')
    result, previous_line = [], 1
    for index, row in enumerate(reader, 1):
        require(None not in row and all(isinstance(v, str) and '\x00' not in v for v in row.values()),
                'Invalid VLoc CSV record')
        require(re.fullmatch(r'[A-Za-z0-9]{8}', row['alpha_id']), 'Invalid VLoc alpha ID')
        require(re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', row['repo_full_name']),
                'Invalid VLoc repository')
        require(re.fullmatch(r'[0-9a-f]{40}', row['merge_commit_sha']), 'Invalid fixed revision')
        require(row['vulnerable_commit_sha'] == '' or re.fullmatch(r'[0-9a-f]{40}', row['vulnerable_commit_sha']),
                'Invalid vulnerable revision')
        for key in ('vulnerable_content_md5', 'merge_content_md5', 'vulnerable_zip_md5', 'merge_zip_md5'):
            require(re.fullmatch(r'[0-9a-f]{32}', row[key]), 'Invalid native MD5')
        for key in ('vulnerable_zip_kb', 'merge_zip_kb', 'vulnerable_unzip_kb', 'merge_unzip_kb', 'n_ground_truth_files'):
            require(re.fullmatch(r'[0-9]+', row[key]), 'Invalid native size/count')
        gt = string_list(row['ground_truth_files'])
        for path in gt:
            safe_path(path)
        require(len(gt) == int(row['n_ground_truth_files']), 'Native file count mismatch')
        require(all(re.fullmatch(r'CWE-[0-9]+', x) for x in string_list(row['cwes'])), 'Invalid CWE')
        string_list(row['cwe_description'])
        require(all(re.fullmatch(r'CVE-[0-9]{4}-[0-9]+', x) for x in string_list(row['cves'], blank=True)), 'Invalid CVE')
        require(not row['ghsa_id'] or re.fullmatch(r'GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}', row['ghsa_id']), 'Invalid GHSA')
        notes = json.loads(row['notes']) if row['notes'] else {}
        require(isinstance(notes, dict), 'Invalid native notes')
        require(row['vulnerable_commit_sha'] or notes.get('error_type') == 'repo_deleted',
                'Missing vulnerable revision without mirror note')
        result.append((index, previous_line + 1, reader.line_num, row))
        previous_line = reader.line_num
    require(result and len({r[3]['alpha_id'] for r in result}) == len(result), 'Empty/duplicate VLoc cases')
    return result


def normalize(rows):
    result = []
    for index, start, end, row in rows:
        issues = []
        if not row['vulnerable_commit_sha']:
            issues.append('missing_vulnerable_revision_requires_mirror')
        if not row['ghsa_id']:
            issues.append('missing_advisory_id')
        if len(string_list(row['cwes'])) != len(string_list(row['cwe_description'])):
            issues.append('native_cwe_id_description_count_mismatch')
        result.append(dict(schema_version='vloc.case.v1', case_id='vloc-' + row['alpha_id'],
            source=dict(repository='https://github.com/' + row['repo_full_name'],
                        vulnerable_commit=row['vulnerable_commit_sha'] or None,
                        fixed_commit=row['merge_commit_sha']),
            model_input=dict(cwe_descriptions=string_list(row['cwe_description'])),
            evaluator_only=dict(native_manifest_row=dict(row),
                                ground_truth_files=filter_ground_truth(string_list(row['ground_truth_files'])),
                                raw_ref=dict(path=RAW, data_row=index, line_start=start,
                                             line_end=end, row_sha256=digest(canonical(row)))),
            status=dict(source_acquisition=('not_acquired' if row['vulnerable_commit_sha'] else 'requires_mirror'),
                        source_review='pending', candidate_pool='not_built', training='not_assessed',
                        evaluation='not_run', issues=issues)))
    return result


def counts(cases):
    rows = [case['evaluator_only']['native_manifest_row'] for case in cases]
    return dict(tasks=len(rows), repositories=len({r['repo_full_name'].lower() for r in rows}),
        nonempty_advisories=len({r['ghsa_id'] for r in rows if r['ghsa_id']}),
        tasks_missing_advisory=sum(not r['ghsa_id'] for r in rows),
        unique_cves=len({cve for r in rows for cve in string_list(r['cves'], blank=True)}),
        vulnerable_snapshots_with_revision=len({(r['repo_full_name'].lower(), r['vulnerable_commit_sha']) for r in rows if r['vulnerable_commit_sha']}),
        fixed_snapshots=len({(r['repo_full_name'].lower(), r['merge_commit_sha']) for r in rows}),
        native_snapshot_pairs=len({(r['repo_full_name'].lower(), r['vulnerable_commit_sha'], r['merge_commit_sha']) for r in rows}),
        fully_revision_pinned_tasks=sum(bool(r['vulnerable_commit_sha']) for r in rows),
        tasks_requiring_mirror=sum(not r['vulnerable_commit_sha'] for r in rows),
        native_ground_truth_file_labels=sum(len(string_list(r['ground_truth_files'])) for r in rows),
        scorer_ground_truth_file_labels=sum(len(c['evaluator_only']['ground_truth_files']) for c in cases),
        tasks_with_empty_scorer_ground_truth=sum(not c['evaluator_only']['ground_truth_files'] for c in cases),
        cwe_ids=len({cwe for r in rows for cwe in string_list(r['cwes'])}),
        tasks_with_empty_cwe_descriptions=sum(not string_list(r['cwe_description']) for r in rows),
        cwe_id_description_count_mismatches=sum(len(string_list(r['cwes'])) != len(string_list(r['cwe_description'])) for r in rows))


def build(blobs):
    cases = normalize(read_rows(blobs[RAW]))
    source = dict(schema_version=1, adapter=VERSION, upstream=dict(repository=UPSTREAM, commit=COMMIT),
                  files={path: dict(sha256=digest(blobs[path]), bytes=len(blobs[path])) for path in PROVENANCE},
                  protocol=PROTOCOL, license=LICENSE)
    summary = dict(schema_version=1, adapter=VERSION, counts=counts(cases),
                   scope='entire_native_manifest_metadata_and_patch_file_labels',
                   status=dict(target_snapshots_acquired=0, source_review='pending',
                               candidate_pool='not_built', evaluation='not_run', training='not_assessed'),
                   known_issues=[dict(case_id=c['case_id'], issues=c['status']['issues'])
                                 for c in cases if c['status']['issues']])
    return {'cases.jsonl': b''.join(canonical(case) + b'\n' for case in cases),
            'source.json': pretty(source), 'summary.json': pretty(summary)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    output = args.output_dir.absolute()
    require(not output.exists() and not output.is_symlink(), 'New output directory required')
    require(all(not parent.is_symlink() for parent in output.parents), 'Symlinked output refused')
    blobs = {path: subprocess.check_output(['git', '-C', str(args.repository), 'show', COMMIT + ':' + path])
             for path in PROVENANCE}
    artifacts = build(blobs)
    output.mkdir(parents=True, exist_ok=False)
    for name, body in artifacts.items():
        with (output / name).open('xb') as handle:
            handle.write(body)
    print(json.dumps(dict(status='normalized_metadata_only', counts=counts(normalize(read_rows(blobs[RAW])))), sort_keys=True))


if __name__ == '__main__':
    main()
