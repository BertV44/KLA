#!/usr/bin/env python3
"""
K10 Log Bundle Anonymizer v3
=============================
Anonymizes sensitive infrastructure data from Kasten K10 support log bundles.

Architecture:
  - Single-read: files cached between detection and replacement
  - Split replacement: non-IP mega-regex + IP pattern + OIDC patterns
  - OIDC tokens handled by regex pattern (not literals) to avoid mega-regex
    explosion when thousands of unique state/code values are present
  - Keyword-gated detection for cheap patterns
  - Optional Aho-Corasick (pip install pyahocorasick) for large pattern sets

Usage:
  python3 k10_log_anonymizer_v3.py <input_dir> <output_dir>
"""

import argparse
import json
import os
import re
import sys
import uuid
from collections import OrderedDict
from pathlib import Path

try:
    import ahocorasick
    HAS_AC = True
except ImportError:
    HAS_AC = False

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

KNOWN_SAFE_NAMESPACES = {
    "default", "kube-system", "kube-public", "kube-node-lease",
    "kasten-io", "kasten-io-mc", "kasten-io-cluster",
    "openshift", "true", "false",
}
SAFE_NAMESPACE_PREFIXES = ("openshift-", "kube-", "kasten-io")
IP_PASSTHROUGH = {"0.0.0.0", "127.0.0.1", "255.255.255.255"}
SAFE_DOMAIN_PATTERNS = {"apps.openshift.io", "apps.kio.kasten", "apiserver.local", "cluster.local"}
SAFE_DOMAIN_SUBSTRINGS = ("kasten.io", "openshift.io", "kubernetes.io")

# ---------------------------------------------------------------------------
# Mapping store
# ---------------------------------------------------------------------------

class MappingStore:
    def __init__(self):
        self._maps: dict[str, OrderedDict] = {}
        self._counters: dict[str, int] = {}

    def get_or_create(self, category, original, fmt_func):
        if category not in self._maps:
            self._maps[category] = OrderedDict()
            self._counters[category] = 0
        if original not in self._maps[category]:
            self._counters[category] += 1
            self._maps[category][original] = fmt_func(self._counters[category])
        return self._maps[category][original]

    def dump(self):
        return {cat: dict(m) for cat, m in self._maps.items()}


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

def detect_and_cache(input_dir: str) -> tuple[dict, list[tuple[str, str, str]]]:
    detected = {
        "cluster_uuids": set(), "cluster_names": set(), "domains": set(),
        "storage_endpoints": set(), "buckets": set(), "ips": set(),
        "namespaces": set(), "access_keys": set(),
        "oidc_codes": set(), "oidc_states": set(),
    }

    # ---- Always-scan patterns ----
    pat_ip = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')

    # [Gap 1] Generalized FQDN: *.apps.* (any TLD) + internal TLDs
    pat_dom = re.compile(
        r'\b('
        r'[a-zA-Z0-9][-a-zA-Z0-9]*\.apps\.[a-zA-Z0-9][-a-zA-Z0-9.]*'
        r'|[a-zA-Z0-9][-a-zA-Z0-9]*\.(?:home|local|lab|corp|internal|lan)'
        r')\b')
    pat_bdom = re.compile(r'apps\.([a-zA-Z0-9][-a-zA-Z0-9.]*)\.([a-z]{2,})\b')
    # [Gap 1] OCP API endpoints: api.xxx.yyy.tld
    pat_api_fqdn = re.compile(r'\bapi\.([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-z]{2,})\b')

    # [Gap 2] S3 full URLs in Kopia HTTP debug logs
    pat_s3_url = re.compile(
        r'https?://(s3[a-zA-Z0-9.]*\.[a-z]{2,}(?:\.[a-z]{2,})*)'
        r'/([a-zA-Z0-9][-a-zA-Z0-9_]*)(?=/)')

    # ---- Gated patterns ----
    gated = [
        ("cluster_name", re.compile(
            r'cluster_name["\s:=>]+["\s]*([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', re.I),
            "cluster_uuids"),
        ("namespace", re.compile(r'namespace[=":>]+\s*"?\s*([a-z0-9][-a-z0-9]*)'),
            "namespaces"),
        ("appName", re.compile(r'appName=([a-z0-9][-a-z0-9]*)'),
            "namespaces"),
        ("bucket", re.compile(r'bucket[=":>]+\s*"?\s*([a-zA-Z0-9][-a-zA-Z0-9_.]*)'),
            "buckets"),
        ("endpoint", re.compile(r'endpoint[=":>]+\s*"?\s*"?(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9.]+\.[a-z]{2,})'),
            "storage_endpoints"),
        ("cluster", re.compile(r'cluster[=":>]+\s*"?\s*([a-zA-Z0-9][-a-zA-Z0-9_]*)"?'),
            "cluster_names"),
        ("accessKeyID", re.compile(r'accessKeyID["\s:=>]+["\s]*([a-zA-Z0-9]{20,})'),
            "access_keys"),
        # [Gap 3] AWS SigV4 Credential= in Authorization headers
        ("Credential=", re.compile(r'Credential=([a-zA-Z0-9]{20,})/'),
            "access_keys"),
        # [Gap 4] OIDC authorization codes
        ("code=", re.compile(r'[?&]code=([a-zA-Z0-9]{20,})'),
            "oidc_codes"),
        # [Gap 5] OIDC state tokens
        ("oidc-auth-state", re.compile(r'state=(oidc-auth-state-[a-zA-Z0-9]+)'),
            "oidc_states"),
    ]

    file_cache = []

    for root, _, files in os.walk(input_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            rel = os.path.relpath(fpath, input_dir)
            try:
                with open(fpath, "r", errors="replace") as f:
                    content = f.read()
            except Exception:
                continue

            file_cache.append((fpath, rel, content))

            for m in pat_ip.finditer(content):
                if m.group(1) not in IP_PASSTHROUGH:
                    detected["ips"].add(m.group(1))

            for m in pat_dom.finditer(content):
                dom = m.group(1).rstrip("/")
                if dom not in SAFE_DOMAIN_PATTERNS and not any(s in dom for s in SAFE_DOMAIN_SUBSTRINGS):
                    detected["domains"].add(dom)
            for m in pat_bdom.finditer(content):
                dom = f"apps.{m.group(1)}.{m.group(2)}"
                if dom not in SAFE_DOMAIN_PATTERNS and not any(s in dom for s in SAFE_DOMAIN_SUBSTRINGS):
                    detected["domains"].add(dom)
                    # Extract OCP cluster name from base domain (apps.CLUSTERNAME.suffix)
                    # e.g. apps.plt-rbx-nsxt.snc.tdp.ovh → plt-rbx-nsxt
                    cluster_part = m.group(1).split(".")[0]
                    if len(cluster_part) >= 3 and cluster_part not in ("apps", "api"):
                        detected["cluster_names"].add(cluster_part)

            for m in pat_api_fqdn.finditer(content):
                full = f"api.{m.group(1)}"
                if not any(s in full for s in SAFE_DOMAIN_SUBSTRINGS):
                    detected["domains"].add(full)

            for m in pat_s3_url.finditer(content):
                ep = m.group(1)
                bkt = m.group(2)
                if not any(x in ep for x in ["svc.cluster", "kasten.io"]):
                    detected["storage_endpoints"].add(ep)
                if not re.match(r'^[0-9a-f]{8}-', bkt):
                    detected["buckets"].add(bkt)

            for keyword, pattern, target in gated:
                if keyword not in content:
                    continue
                for m in pattern.finditer(content):
                    val = m.group(1)
                    if target == "namespaces":
                        if len(val) >= 2 and val not in KNOWN_SAFE_NAMESPACES and not val.startswith(SAFE_NAMESPACE_PREFIXES):
                            detected[target].add(val)
                    elif target == "storage_endpoints":
                        if not any(x in val for x in ["svc.cluster", "kasten.io", "kubernetes.io"]):
                            detected[target].add(val)
                    elif target == "cluster_names":
                        if len(val) < 20 and val not in ("true", "false", "live"):
                            detected[target].add(val)
                    elif target == "cluster_uuids":
                        detected[target].add(val.lower())
                    else:
                        detected[target].add(val)

    return {k: sorted(v) for k, v in detected.items()}, file_cache


# ---------------------------------------------------------------------------
# Build replacer
# ---------------------------------------------------------------------------

def build_replacer(detected: dict):
    store = MappingStore()
    non_ip_lookup = {}
    ip_lookup = {}
    short_ns_lookup = {}

    for uid in detected.get("cluster_uuids", []):
        r = store.get_or_create("cluster_uuid", uid,
            lambda n: str(uuid.UUID(int=0xABCDEF0000000000 + n)))
        non_ip_lookup[uid] = r
        non_ip_lookup[uid.upper()] = r

    for cn in detected.get("cluster_names", []):
        r = store.get_or_create("cluster_name", cn, lambda n: f"cluster{n:02d}")
        if len(cn) >= 3:
            non_ip_lookup[cn] = r

    for dom in sorted(detected.get("domains", []), key=len, reverse=True):
        r = store.get_or_create("domain", dom, lambda n: f"redacted-host{n:02d}.example.internal")
        non_ip_lookup[dom] = r

    for ep in detected.get("storage_endpoints", []):
        r = store.get_or_create("storage_endpoint", ep, lambda n: f"s3.anon-storage{n:02d}.example.com")
        non_ip_lookup[ep] = r

    for bkt in detected.get("buckets", []):
        r = store.get_or_create("bucket_name", bkt, lambda n: f"anon-bucket-{n:03d}")
        non_ip_lookup[bkt] = r

    for ak in detected.get("access_keys", []):
        r = store.get_or_create("access_key", ak, lambda n: f"REDACTED_ACCESS_KEY_{n:03d}")
        non_ip_lookup[ak] = r

    # [Gap 6] Namespaces: >= 4 chars go in mega-regex, < 4 go contextual
    for ns in detected.get("namespaces", []):
        r = store.get_or_create("namespace", ns, lambda n: f"app-ns-{n:03d}")
        if len(ns) >= 4:
            non_ip_lookup[ns] = r
        else:
            short_ns_lookup[ns] = r

    # [Gap 4+5] OIDC: pre-seed mapping for the summary, but replace by PATTERN
    # not by literal. This keeps the mega-regex small (no 2500+ extra entries).
    oidc_code_map = {}
    for code in detected.get("oidc_codes", []):
        r = store.get_or_create("oidc_code", code, lambda n: f"REDACTED_OIDC_CODE_{n:04d}")
        oidc_code_map[code] = r

    oidc_state_map = {}
    for state in detected.get("oidc_states", []):
        r = store.get_or_create("oidc_state", state, lambda n: f"oidc-auth-state-redacted-{n:04d}")
        oidc_state_map[state] = r

    # IPs: pattern-based
    for ip in detected.get("ips", []):
        if ip not in IP_PASSTHROUGH:
            r = store.get_or_create("ip_address", ip,
                lambda n: f"198.51.{(n // 256) % 256}.{n % 256}")
            ip_lookup[ip] = r

    # ---- Build non-IP literal matcher (no OIDC, no short ns) ----
    if HAS_AC:
        automaton = ahocorasick.Automaton()
        for original, replacement in non_ip_lookup.items():
            automaton.add_word(original, (original, replacement))
        automaton.make_automaton()
        def replace_literals(text: str) -> str:
            result = []
            last_end = 0
            for end_idx, (original, replacement) in automaton.iter(text):
                start_idx = end_idx - len(original) + 1
                if start_idx >= last_end:
                    result.append(text[last_end:start_idx])
                    result.append(replacement)
                    last_end = end_idx + 1
            result.append(text[last_end:])
            return "".join(result)
    else:
        literals = sorted(non_ip_lookup.keys(), key=len, reverse=True)
        if literals:
            mega = re.compile("|".join(re.escape(lit) for lit in literals))
            replace_literals = lambda text: mega.sub(
                lambda m: non_ip_lookup[m.group(0)], text)
        else:
            replace_literals = lambda text: text

    ip_pattern = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')

    # [Gap 4] OIDC code pattern: replace code=xxx with dict lookup
    oidc_code_pat = re.compile(r'([?&]code=)([a-zA-Z0-9]{20,})')
    # [Gap 5] OIDC state pattern: replace state=oidc-auth-state-xxx
    oidc_state_pat = re.compile(r'(state=)(oidc-auth-state-[a-zA-Z0-9]+)')

    # [Gap 6] Short namespace contextual patterns
    short_ns_patterns = []
    for ns, replacement in short_ns_lookup.items():
        escaped = re.escape(ns)
        short_ns_patterns.append((
            re.compile(
                r'(namespace[=":>]+\s*"?)' + escaped + r'("?)'
                r'|("namespace"\s*=>\s*")' + escaped + r'(")'
                r'|(/namespaces/)' + escaped + r'(?=/|"|\s|$)'
                r'|(appName=)' + escaped + r'(?=&|"|\s|$)'
            ),
            ns, replacement
        ))

    def replace_content(text: str) -> str:
        # Pass 1: non-IP literals (domains, UUIDs, endpoints, keys, ns>=4, buckets, clusters)
        text = replace_literals(text)
        # Pass 2: IPs
        text = ip_pattern.sub(lambda m: ip_lookup.get(m.group(0), m.group(0)), text)
        # Pass 3: OIDC codes (pattern-based, dict lookup)
        if oidc_code_map:
            text = oidc_code_pat.sub(
                lambda m: m.group(1) + oidc_code_map.get(m.group(2), m.group(2)), text)
        # Pass 4: OIDC states (pattern-based, dict lookup)
        if oidc_state_map:
            text = oidc_state_pat.sub(
                lambda m: m.group(1) + oidc_state_map.get(m.group(2), m.group(2)), text)
        # Pass 5: short namespaces (contextual only)
        for pat, ns, replacement in short_ns_patterns:
            def _sub(m, _r=replacement):
                if m.group(1) is not None:
                    return m.group(1) + _r + (m.group(2) or "")
                elif m.group(3) is not None:
                    return m.group(3) + _r + m.group(4)
                elif m.group(5) is not None:
                    return m.group(5) + _r
                elif m.group(6) is not None:
                    return m.group(6) + _r
                return m.group(0)
            text = pat.sub(_sub, text)
        return text

    return replace_content, store


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def process_bundle(input_dir: str, output_dir: str):
    import time
    t0 = time.time()

    print(f"[*] Scanning {input_dir} (single-read with caching)...")
    detected, file_cache = detect_and_cache(input_dir)
    t_detect = time.time()

    total_bytes = sum(len(c) for _, _, c in file_cache)
    total_mb = total_bytes / 1048576
    print(f"    Cached {len(file_cache)} files ({total_mb:.1f} MB) in {t_detect - t0:.2f}s")

    print(f"\n[*] Detected values to anonymize:")
    total_patterns = 0
    for cat, values in detected.items():
        print(f"    {cat}: {len(values)} unique value(s)")
        total_patterns += len(values)
        for v in values[:3]:
            print(f"      - {v}")
        if len(values) > 3:
            print(f"      ... and {len(values) - 3} more")

    replace_func, store = build_replacer(detected)
    t_build = time.time()

    n_non_ip = total_patterns - len(detected.get("ips", []))
    n_ip = len(detected.get("ips", []))
    backend = "Aho-Corasick" if HAS_AC else "mega-regex"
    print(f"\n[*] Replacement: {backend} + IP pattern ({n_ip}) + OIDC patterns + short-ns patterns")

    os.makedirs(output_dir, exist_ok=True)

    file_count = 0
    for _, rel, content in file_cache:
        dst = os.path.join(output_dir, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        try:
            result = replace_func(content)
            with open(dst, "w") as f:
                f.write(result)
            file_count += 1
        except Exception as e:
            print(f"    [!] Skipped {rel}: {e}")
    t_replace = time.time()

    mapping_path = os.path.join(output_dir, "_anonymization_mapping.json")
    mapping = store.dump()
    with open(mapping_path, "w") as f:
        json.dump(mapping, f, indent=2)

    summary_path = os.path.join(output_dir, "_anonymization_summary.txt")
    with open(summary_path, "w") as f:
        f.write("K10 Log Bundle Anonymization Summary\n")
        f.write("=" * 50 + "\n\n")
        for cat, entries in mapping.items():
            f.write(f"[{cat}] ({len(entries)} entries)\n")
            f.write("-" * 40 + "\n")
            if len(entries) <= 50:
                for orig, anon in entries.items():
                    f.write(f"  {orig:<60s} -> {anon}\n")
            else:
                shown = list(entries.items())
                for orig, anon in shown[:10]:
                    f.write(f"  {orig:<60s} -> {anon}\n")
                f.write(f"  ... ({len(entries) - 10} more entries, see JSON for full list)\n")
            f.write("\n")

    t_end = time.time()
    rate = total_mb / (t_end - t0) if (t_end - t0) > 0 else 0

    print(f"\n[+] Anonymized {file_count} files -> {output_dir}/")
    print(f"[+] Mapping table -> {mapping_path}")
    print(f"[+] Timing: detect {t_detect-t0:.2f}s + build {t_build-t_detect:.2f}s "
          f"+ replace {t_replace-t_build:.2f}s + write {t_end-t_replace:.2f}s "
          f"= {t_end-t0:.2f}s total")
    print(f"[+] Throughput: {rate:.1f} MB/s ({total_patterns} patterns)")
    print(f"\n    Keep the mapping JSON safe – it's the only way to reverse the anonymization.")


def main():
    parser = argparse.ArgumentParser(description="Anonymize K10 log bundles (fully optimized)")
    parser.add_argument("input_dir", help="Path to extracted K10 log bundle")
    parser.add_argument("output_dir", help="Destination for anonymized logs")
    args = parser.parse_args()
    if not os.path.isdir(args.input_dir):
        print(f"Error: {args.input_dir} is not a directory")
        sys.exit(1)
    process_bundle(args.input_dir, args.output_dir)


if __name__ == "__main__":
    main()
