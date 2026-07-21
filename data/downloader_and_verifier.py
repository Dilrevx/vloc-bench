# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Download repos from GitHub and verify against content MD5s in manifest.

Sources and resolution strategy (500 entries total):
  All 500 entries are downloaded as zip archives from GitHub at the exact commit
  SHA recorded in manifest.csv (vulnerable_commit_sha / merge_commit_sha).
  URL pattern: https://github.com/{repo_full_name}/archive/{commit_sha}.zip

GitHub archive zips differ from git-clone zips in three ways that must be
resolved to reproduce the original dataset:

  1. Top-level directory prefix: GitHub wraps all files under
     "{reponame}-{commit_sha}/". We strip this prefix to produce flat paths
     matching the eval harness expectation.

  2. Symlinks: GitHub archives store symlinks as regular file entries whose
     content is the symlink target string. Identified via Unix external
     attributes (stat.S_ISLNK on info.external_attr >> 16).
     Resolution:
     - File symlinks (target resolves to a regular file): replaced with the
       target file's content. Supports multi-hop resolution (symlink through a
       directory symlink, e.g. quarkusio/quarkus has provider -> .hidden-symlink-dir/provider
       where .hidden-symlink-dir -> .hidden-dir/).
     - Directory symlinks (target is a directory or unresolvable): skipped
       entirely (not included in output). The original dataset also excluded these.

  3. Git export-subst: Files with `.gitattributes` declaring `export-subst` get
     `$Format:%h$` expanded to an abbreviated commit hash. GitHub's archive
     service uses a longer abbreviation (2 extra hex chars) than git-clone.
     Affects `*/version/base.go` in kubernetes/kubernetes, kubeedge/kubeedge,
     grafana/loki (via vendored k8s client-go), and hashicorp/consul.
     Fix: detect lines matching the pattern `"v0.0.0-master+<hex>"` and truncate
     the abbreviated hash by 2 characters to match the git-clone expansion.
     Exception: when the hex is already 40 chars (full SHA1), both GitHub and
     git-clone produce identical output, so no trimming is applied. This occurs
     for 7 kubernetes, 3 kubeedge, and 1 loki entry.

Verification — content-based MD5:
  After all transformations, we compute a deterministic hash over the file tree:
  md5(for each file in lexicographic path order: path.encode('utf-8') + file_bytes).
  This is compared against vulnerable_content_md5 / merge_content_md5 in manifest.csv.

  The original zip-level hashes (vulnerable_zip_md5 / merge_zip_md5) are retained
  in manifest.csv for anyone who cached the original HF dataset zips. They are NOT
  used by this script — GitHub regenerates zip metadata non-deterministically.

Coverage: 500/500 entries verify with all three resolution steps applied.

Output layout:
  data/ghsa-vulns/{alpha_id}/pre_push.zip   (vulnerable commit, flat zip)
  data/ghsa-vulns/{alpha_id}/post_push.zip  (merge commit, flat zip)

Usage:
  python data/downloader_and_verifier.py --workers 16
  python data/downloader_and_verifier.py --workers 16 --resume
"""

import argparse
import csv
import hashlib
import io
import json
import os
import posixpath
import re
import shutil
import stat
import sys
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from tqdm import tqdm

_EXPORT_SUBST_RE = re.compile(
    rb'("v0\.0\.0-master\+)([0-9a-f]{9,})(")'
)


def _is_symlink(info):
    """Check if a zip entry is a symlink via Unix external attributes."""
    unix_attrs = info.external_attr >> 16
    return stat.S_ISLNK(unix_attrs) if unix_attrs else False


def _resolve_symlink_path(path, symlinks, max_depth=10):
    """Resolve a path through any directory symlinks in its components."""
    for _ in range(max_depth):
        parts = path.split("/")
        resolved = False
        if path in symlinks:
            target = symlinks[path]
            base_dir = posixpath.dirname(path)
            path = posixpath.normpath(posixpath.join(base_dir, target))
            resolved = True
            continue
        for i in range(1, len(parts)):
            prefix = "/".join(parts[:i])
            if prefix in symlinks:
                target = symlinks[prefix].rstrip("/")
                base_dir = posixpath.dirname(prefix)
                resolved_prefix = posixpath.normpath(posixpath.join(base_dir, target))
                remainder = "/".join(parts[i:])
                path = posixpath.join(resolved_prefix, remainder)
                resolved = True
                break
        if not resolved:
            break
    return path


def _normalize_export_subst(data, path):
    """Truncate GitHub's longer %h expansion to match git-clone length.

    GitHub expands $Format:%h$ with 2 extra hex chars vs git clone. We detect
    the pattern and trim the last 2 chars of the abbreviated hash.
    Only applied to */version/base.go files (the only known export-subst case).

    Exception: when the expanded hash is already 40 hex chars (full SHA1), both
    GitHub and git-clone produce identical output — no trimming needed. This
    happens for some kubernetes/kubernetes commits (and vendored copies in
    kubeedge/kubeedge, grafana/loki) where git's abbreviation length equals the
    full hash length.
    """
    if not path.endswith("version/base.go"):
        return data

    def _trim(m):
        prefix = m.group(1)
        hexstr = m.group(2)
        suffix = m.group(3)
        # Full 40-char SHA means both sources agree — don't trim
        if len(hexstr) == 40:
            return m.group(0)
        return prefix + hexstr[:-2] + suffix

    return _EXPORT_SUBST_RE.sub(_trim, data)


def _read_zip_entries(z, strip_prefix=None):
    """Read all file entries from a zip, resolving symlinks and export-subst.

    Returns dict of {relative_path: file_bytes}.
    """
    entries = {}
    symlinks = {}

    for info in z.infolist():
        if info.is_dir():
            continue
        path = info.filename
        if strip_prefix and path.startswith(strip_prefix):
            path = path[len(strip_prefix):]
        data = z.read(info.filename)

        if _is_symlink(info):
            symlinks[path] = data.decode("utf-8").strip()
        else:
            data = _normalize_export_subst(data, path)
            entries[path] = data

    for sym_path, target in symlinks.items():
        sym_dir = posixpath.dirname(sym_path)
        resolved = posixpath.normpath(posixpath.join(sym_dir, target))
        final_path = _resolve_symlink_path(resolved, symlinks)

        if final_path in entries:
            entries[sym_path] = entries[final_path]
        elif resolved in entries:
            entries[sym_path] = entries[resolved]
        else:
            if not target.endswith("/"):
                pass

    return entries


def content_hash_from_zip(zippath, strip_prefix=None):
    """Compute deterministic content MD5 from a zip file."""
    with zipfile.ZipFile(zippath) as z:
        entries = _read_zip_entries(z, strip_prefix)
    h = hashlib.md5()
    for path, data in sorted(entries.items()):
        h.update(path.encode("utf-8"))
        h.update(data)
    return h.hexdigest()


def content_hash_from_bytes(zip_bytes, strip_prefix=None):
    """Same as content_hash_from_zip but from in-memory bytes."""
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
        entries = _read_zip_entries(z, strip_prefix)
    h = hashlib.md5()
    for path, data in sorted(entries.items()):
        h.update(path.encode("utf-8"))
        h.update(data)
    return h.hexdigest()


def repack_flat(zip_bytes, strip_prefix):
    """Re-pack a GitHub archive zip as a flat zip with symlinks resolved."""
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
        entries = _read_zip_entries(z, strip_prefix)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as dst:
        for path, data in sorted(entries.items()):
            dst.writestr(path, data)
    return buf.getvalue()


def download_with_retry(url, max_retries=3, timeout=120):
    """Download URL content with retries and exponential backoff."""
    for attempt in range(max_retries):
        try:
            req = Request(url, headers={"User-Agent": "vulnerability-localization-benchmark-downloader/1.0"})
            with urlopen(req, timeout=timeout) as resp:
                return resp.read()
        except (HTTPError, URLError, TimeoutError) as e:
            if isinstance(e, HTTPError) and e.code == 404:
                raise
            if attempt == max_retries - 1:
                raise
            time.sleep(2 ** attempt)
    return None


def get_github_prefix(zip_bytes):
    """Extract the top-level directory prefix from a GitHub archive zip."""
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
        first = z.namelist()[0]
        if first.endswith("/"):
            return first
        return first.split("/")[0] + "/"


def is_mirror_entry(row):
    notes = row.get("notes", "")
    if not notes:
        return False
    try:
        parsed = json.loads(notes)
        return parsed.get("error_type") == "repo_deleted"
    except (json.JSONDecodeError, TypeError):
        return False


def process_entry(row, output_dir, mirror_dir, resume=False):
    """Download, verify, and save zips for one manifest entry."""
    alpha_id = row["alpha_id"]
    repo = row["repo_full_name"]
    vuln_sha = row["vulnerable_commit_sha"]
    merge_sha = row["merge_commit_sha"]
    expected_vuln_md5 = row["vulnerable_content_md5"]
    expected_merge_md5 = row["merge_content_md5"]

    dst_dir = os.path.join(output_dir, alpha_id)
    dst_pre = os.path.join(dst_dir, "pre_push.zip")
    dst_post = os.path.join(dst_dir, "post_push.zip")

    if resume and os.path.exists(dst_pre) and os.path.exists(dst_post):
        pre_ok = content_hash_from_zip(dst_pre) == expected_vuln_md5
        post_ok = content_hash_from_zip(dst_post) == expected_merge_md5
        if pre_ok and post_ok:
            return alpha_id, "skip", "already verified"

    os.makedirs(dst_dir, exist_ok=True)

    if is_mirror_entry(row):
        ghsa_id = row["ghsa_id"]
        src_pre = os.path.join(mirror_dir, ghsa_id, "pre_push.zip")
        src_post = os.path.join(mirror_dir, ghsa_id, "post_push.zip")
        if not os.path.exists(src_pre) or not os.path.exists(src_post):
            return alpha_id, "FAIL", f"mirror missing: {src_pre}"
        shutil.copy2(src_pre, dst_pre)
        shutil.copy2(src_post, dst_post)
        pre_hash = content_hash_from_zip(dst_pre)
        post_hash = content_hash_from_zip(dst_post)
    else:
        pre_url = f"https://github.com/{repo}/archive/{vuln_sha}.zip"
        post_url = f"https://github.com/{repo}/archive/{merge_sha}.zip"

        try:
            pre_bytes = download_with_retry(pre_url)
        except HTTPError as e:
            return alpha_id, "FAIL", f"pre_push download HTTP {e.code}: {pre_url}"
        except Exception as e:
            return alpha_id, "FAIL", f"pre_push download failed: {e}"

        try:
            post_bytes = download_with_retry(post_url)
        except HTTPError as e:
            return alpha_id, "FAIL", f"post_push download HTTP {e.code}: {post_url}"
        except Exception as e:
            return alpha_id, "FAIL", f"post_push download failed: {e}"

        pre_prefix = get_github_prefix(pre_bytes)
        post_prefix = get_github_prefix(post_bytes)

        pre_hash = content_hash_from_bytes(pre_bytes, pre_prefix)
        post_hash = content_hash_from_bytes(post_bytes, post_prefix)

        pre_flat = repack_flat(pre_bytes, pre_prefix)
        post_flat = repack_flat(post_bytes, post_prefix)

        with open(dst_pre, "wb") as f:
            f.write(pre_flat)
        with open(dst_post, "wb") as f:
            f.write(post_flat)

    errors = []
    if pre_hash != expected_vuln_md5:
        errors.append(f"pre_push: got {pre_hash}, expected {expected_vuln_md5}")
    if post_hash != expected_merge_md5:
        errors.append(f"post_push: got {post_hash}, expected {expected_merge_md5}")

    if errors:
        for p in [dst_pre, dst_post]:
            if os.path.exists(p):
                os.remove(p)
        return alpha_id, "FAIL", "; ".join(errors)

    return alpha_id, "ok", ""


def main():
    parser = argparse.ArgumentParser(
        description="Download eval dataset from GitHub and verify content MD5s"
    )
    script_dir = os.path.dirname(os.path.abspath(__file__))
    parser.add_argument(
        "--manifest", default=os.path.join(script_dir, "manifest.csv"),
        help="Path to manifest.csv (500 entries)"
    )
    parser.add_argument(
        "--mirror-dir", default=os.path.join(script_dir, "deleted-repo-mirrors"),
        help="Directory with mirrored zips for deleted repos ({ghsa_id}/*.zip)"
    )
    parser.add_argument(
        "--output-dir", default=os.path.join(script_dir, "ghsa-vulns"),
        help="Where to save verified zips ({alpha_id}/pre_push.zip)"
    )
    parser.add_argument("--workers", type=int, default=8, help="Parallel download workers")
    parser.add_argument("--resume", action="store_true", help="Skip already-verified entries")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    with open(args.manifest) as f:
        rows = list(csv.DictReader(f))

    mirror_count = sum(1 for r in rows if is_mirror_entry(r))
    print(f"Processing {len(rows)} entries ({len(rows) - mirror_count} from GitHub, {mirror_count} from mirror)")
    print(f"Output: {args.output_dir}")
    if args.resume:
        print("Resume mode: skipping already-verified entries")

    ok = 0
    skip = 0
    failures = []

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(process_entry, row, args.output_dir, args.mirror_dir, args.resume): row["alpha_id"]
            for row in rows
        }

        with tqdm(total=len(futures), desc="Download+Verify") as pbar:
            for future in as_completed(futures):
                alpha_id = futures[future]
                try:
                    aid, status, detail = future.result()
                except Exception as e:
                    aid, status, detail = alpha_id, "FAIL", str(e)[:300]

                if status == "ok":
                    ok += 1
                elif status == "skip":
                    skip += 1
                else:
                    failures.append((aid, status, detail))

                pbar.set_postfix(ok=ok + skip, fail=len(failures))
                pbar.update(1)

    sep = "=" * 60
    print(f"\n{sep}")
    print(f"PASSED: {ok + skip}/{len(rows)}")
    print(f"  Fresh downloaded+verified: {ok}")
    print(f"  Already verified (skipped): {skip}")

    if failures:
        print(f"\nFAILED: {len(failures)}")
        for aid, status, detail in sorted(failures):
            print(f"  {aid}: {detail}")
        sys.exit(1)
    else:
        print(f"\nAll {len(rows)} entries verified. Dataset integrity confirmed.")


if __name__ == "__main__":
    main()
