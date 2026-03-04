#!/usr/bin/env python3
"""
K10 Log Bundle Anonymizer
=========================
Anonymizes sensitive infrastructure data from Kasten K10 support log bundles
while preserving log structure and debuggability.

Targeted categories:
  1. Cluster identity (UUIDs, cluster names)
  2. External FQDNs / OpenShift routes
  3. Object storage endpoints, bucket names, repo paths, access keys
  5. Internal IP addresses
  7. Customer workload namespaces

A reversible mapping table (JSON) is produced alongside the sanitized output.

Usage:
  python3 k10_log_anonymizer.py <input_dir> <output_dir>
  python3 k10_log_anonymizer.py k10logs/k10logs anonymized_logs
"""

import argparse
import json
import os
import re
import sys
import uuid
from collections import OrderedDict
from pathlib import Path


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

KNOWN_SAFE_NAMESPACES = {
    "default",
    "kube-system",
    "kube-public",
    "kube-node-lease",
    "kasten-io",
    "kasten-io-mc",
    "kasten-io-cluster",
    "openshift",
    "true",
    "false",
}

SAFE_NAMESPACE_PREFIXES = (
    "openshift-",
    "kube-",
    "kasten-io",
)

IP_PASSTHROUGH = {
    "0.0.0.0",
    "127.0.0.1",
    "255.255.255.255",
}

SAFE_DOMAIN_PATTERNS = {
    "apps.openshift.io",
    "apps.kio.kasten",
    "apiserver.local",
}
SAFE_DOMAIN_SUBSTRINGS = (
    "kasten.io",
    "openshift.io",
    "kubernetes.io",
)


# ---------------------------------------------------------------------------
# Mapping store
# ---------------------------------------------------------------------------

class MappingStore:
    def __init__(self):
        self._maps: dict[str, OrderedDict] = {}
        self._counters: dict[str, int] = {}

    def get_or_create(self, category: str, original: str, fmt_func) -> str:
        if category not in self._maps:
            self._maps[category] = OrderedDict()
            self._counters[category] = 0
        if original not in self._maps[category]:
            self._counters[category] += 1
            self._maps[category][original] = fmt_func(self._counters[category])
        return self._maps[category][original]

    def dump(self) -> dict:
        return {cat: dict(m) for cat, m in self._maps.items()}


store = MappingStore()


# ---------------------------------------------------------------------------
# Replacement helpers
# ---------------------------------------------------------------------------

def anon_uuid(original: str) -> str:
    def _fmt(n):
        return str(uuid.UUID(int=0xABCDEF0000000000 + n))
    return store.get_or_create("cluster_uuid", original, _fmt)

def anon_cluster_name(original: str) -> str:
    return store.get_or_create("cluster_name", original, lambda n: f"cluster{n:02d}")

def anon_domain(original: str) -> str:
    return store.get_or_create("domain", original, lambda n: f"redacted-host{n:02d}.example.internal")

def anon_storage_endpoint(original: str) -> str:
    return store.get_or_create("storage_endpoint", original, lambda n: f"s3.anon-storage{n:02d}.example.com")

def anon_bucket(original: str) -> str:
    return store.get_or_create("bucket_name", original, lambda n: f"anon-bucket-{n:03d}")

def anon_ip(original: str) -> str:
    if original in IP_PASSTHROUGH:
        return original
    return store.get_or_create("ip_address", original,
        lambda n: f"198.51.{(n // 256) % 256}.{n % 256}")

def anon_namespace(original: str) -> str:
    if original in KNOWN_SAFE_NAMESPACES or original.startswith(SAFE_NAMESPACE_PREFIXES):
        return original
    return store.get_or_create("namespace", original, lambda n: f"app-ns-{n:03d}")

def anon_access_key(original: str) -> str:
    return store.get_or_create("access_key", original, lambda n: f"REDACTED_ACCESS_KEY_{n:03d}")


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

def detect_values(input_dir: str) -> dict:
    detected = {
        "cluster_uuids": set(),
        "cluster_names": set(),
        "domains": set(),
        "storage_endpoints": set(),
        "buckets": set(),
        "ips": set(),
        "namespaces": set(),
        "access_keys": set(),
    }

    cluster_uuid_re = re.compile(
        r'cluster_name["\s:=>]+["\s]*([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', re.I)
    ip_re = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
    fqdn_re = re.compile(
        r'\b([a-zA-Z0-9][-a-zA-Z0-9]*\.apps\.[a-zA-Z0-9][-a-zA-Z0-9.]*'
        r'|[a-zA-Z0-9][-a-zA-Z0-9]*\.(?:home|local|lab|corp|internal|lan))\b')
    base_domain_re = re.compile(r'apps\.([a-zA-Z0-9][-a-zA-Z0-9]*)\.([a-z]+)\b')
    ns_re = re.compile(r'namespace[=":>]+\s*"?\s*([a-z0-9][-a-z0-9]*)')
    bucket_re = re.compile(r'bucket[=":>]+\s*"?\s*([a-zA-Z0-9][-a-zA-Z0-9_.]*)')
    endpoint_re = re.compile(
        r'endpoint[=":>]+\s*"?\s*"?(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9.]+\.[a-z]{2,})')
    cluster_name_re = re.compile(r'cluster[=":>]+\s*"?\s*([a-zA-Z0-9][-a-zA-Z0-9_]*)"?')
    access_key_re = re.compile(r'accessKeyID["\s:=>]+["\s]*([a-zA-Z0-9]{20,})')

    for root, _, files in os.walk(input_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", errors="replace") as f:
                    content = f.read()
            except Exception:
                continue

            for m in cluster_uuid_re.finditer(content):
                detected["cluster_uuids"].add(m.group(1).lower())
            for m in ip_re.finditer(content):
                if m.group(1) not in IP_PASSTHROUGH:
                    detected["ips"].add(m.group(1))
            for m in fqdn_re.finditer(content):
                dom = m.group(1).rstrip("/")
                if dom not in SAFE_DOMAIN_PATTERNS and not any(s in dom for s in SAFE_DOMAIN_SUBSTRINGS):
                    detected["domains"].add(dom)
            for m in base_domain_re.finditer(content):
                dom = f"apps.{m.group(1)}.{m.group(2)}"
                if dom not in SAFE_DOMAIN_PATTERNS and not any(s in dom for s in SAFE_DOMAIN_SUBSTRINGS):
                    detected["domains"].add(dom)
            for m in ns_re.finditer(content):
                ns = m.group(1)
                if ns not in KNOWN_SAFE_NAMESPACES and not ns.startswith(SAFE_NAMESPACE_PREFIXES):
                    detected["namespaces"].add(ns)
            for m in bucket_re.finditer(content):
                detected["buckets"].add(m.group(1))
            for m in endpoint_re.finditer(content):
                ep = m.group(1)
                if not any(x in ep for x in ["svc.cluster", "kasten.io", "kubernetes.io"]):
                    detected["storage_endpoints"].add(ep)
            for m in cluster_name_re.finditer(content):
                cn = m.group(1)
                if len(cn) < 20 and cn not in ("true", "false", "live"):
                    detected["cluster_names"].add(cn)
            for m in access_key_re.finditer(content):
                detected["access_keys"].add(m.group(1))

    return {k: sorted(v) for k, v in detected.items()}


# ---------------------------------------------------------------------------
# Replacement engine
# ---------------------------------------------------------------------------

def build_replacer(detected: dict):
    # Pre-seed mappings
    for uid in detected.get("cluster_uuids", []):
        anon_uuid(uid)
    for cn in detected.get("cluster_names", []):
        anon_cluster_name(cn)
    for dom in detected.get("domains", []):
        anon_domain(dom)
    for ep in detected.get("storage_endpoints", []):
        anon_storage_endpoint(ep)
    for bkt in detected.get("buckets", []):
        anon_bucket(bkt)
    for ak in detected.get("access_keys", []):
        anon_access_key(ak)

    def replace_line(line: str) -> str:
        # --- 1a. Cluster UUIDs ---
        for orig in detected.get("cluster_uuids", []):
            if orig in line.lower():
                line = re.sub(re.escape(orig), anon_uuid(orig), line, flags=re.I)

        # --- 2. Domains / FQDNs (longest first) ---
        for orig in sorted(detected.get("domains", []), key=len, reverse=True):
            if orig in line:
                line = line.replace(orig, anon_domain(orig))

        # --- 3a. Storage endpoints ---
        for orig in sorted(detected.get("storage_endpoints", []), key=len, reverse=True):
            if orig in line:
                line = line.replace(orig, anon_storage_endpoint(orig))

        # --- 3b. Bucket names ---
        for orig in sorted(detected.get("buckets", []), key=len, reverse=True):
            line = re.sub(r'(bucket=)"' + re.escape(orig) + r'"',
                          r'\g<1>"' + anon_bucket(orig) + '"', line)
            line = re.sub(r'(bucket[=":]+\s{0,2})"?' + re.escape(orig) + r'"?',
                          r'\g<1>' + anon_bucket(orig), line)

        # --- 3c. S3 access keys ---
        for orig in detected.get("access_keys", []):
            if orig in line:
                line = line.replace(orig, anon_access_key(orig))

        # --- 1b. Cluster short names (contextual) ---
        for orig in sorted(detected.get("cluster_names", []), key=len, reverse=True):
            line = re.sub(r'cluster="' + re.escape(orig) + r'"',
                          f'cluster="{anon_cluster_name(orig)}"', line)
            line = re.sub(r'cluster[=:]\s*' + re.escape(orig) + r'\b',
                          f'cluster={anon_cluster_name(orig)}', line)

        # --- 5. IP addresses ---
        line = re.sub(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b',
                       lambda m: anon_ip(m.group(0)), line)

        # --- 7. Namespaces (multiple log formats) ---
        for orig in sorted(detected.get("namespaces", []), key=len, reverse=True):
            # Standard: namespace="xxx" or namespace:xxx
            line = re.sub(r'(namespace[=":]+\s*"?)' + re.escape(orig) + r'("?)',
                          r'\g<1>' + anon_namespace(orig) + r'\2', line)
            # Path: /namespaces/xxx/
            line = re.sub(r'/namespaces/' + re.escape(orig) + r'(?=/|"|\s|$)',
                          f'/namespaces/{anon_namespace(orig)}', line)
            # Fluentd: "namespace"=>"xxx"
            line = re.sub(r'("namespace"\s*=>\s*")' + re.escape(orig) + r'"',
                          r'\g<1>' + anon_namespace(orig) + '"', line)
            # Generic word-boundary for ns in policy names, subject refs
            if len(orig) >= 4:
                line = re.sub(r'\b' + re.escape(orig) + r'\b', anon_namespace(orig), line)

        # --- Final: broad cluster name replacement ---
        for orig in sorted(detected.get("cluster_names", []), key=len, reverse=True):
            if len(orig) >= 3:
                line = re.sub(r'\b' + re.escape(orig) + r'\b', anon_cluster_name(orig), line)

        return line

    return replace_line


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def process_bundle(input_dir: str, output_dir: str):
    print(f"[*] Scanning {input_dir} for sensitive values...")
    detected = detect_values(input_dir)

    print(f"\n[*] Detected values to anonymize:")
    for cat, values in detected.items():
        print(f"    {cat}: {len(values)} unique value(s)")
        for v in values[:5]:
            print(f"      - {v}")
        if len(values) > 5:
            print(f"      ... and {len(values) - 5} more")

    replacer = build_replacer(detected)
    os.makedirs(output_dir, exist_ok=True)

    file_count = 0
    for root, dirs, files in os.walk(input_dir):
        rel_root = os.path.relpath(root, input_dir)
        dest_root = os.path.join(output_dir, rel_root)
        os.makedirs(dest_root, exist_ok=True)

        for fname in files:
            src = os.path.join(root, fname)
            dst = os.path.join(dest_root, fname)
            try:
                with open(src, "r", errors="replace") as fin:
                    lines = fin.readlines()
                with open(dst, "w") as fout:
                    for line in lines:
                        fout.write(replacer(line))
                file_count += 1
            except Exception as e:
                print(f"    [!] Skipped {src}: {e}")

    # Mapping table
    mapping_path = os.path.join(output_dir, "_anonymization_mapping.json")
    mapping = store.dump()
    with open(mapping_path, "w") as f:
        json.dump(mapping, f, indent=2)

    # Human-friendly summary
    summary_path = os.path.join(output_dir, "_anonymization_summary.txt")
    with open(summary_path, "w") as f:
        f.write("K10 Log Bundle Anonymization Summary\n")
        f.write("=" * 50 + "\n\n")
        for cat, entries in mapping.items():
            f.write(f"[{cat}] ({len(entries)} entries)\n")
            f.write("-" * 40 + "\n")
            for orig, anon in entries.items():
                f.write(f"  {orig:<50s} -> {anon}\n")
            f.write("\n")

    print(f"\n[+] Anonymized {file_count} files -> {output_dir}/")
    print(f"[+] Mapping table -> {mapping_path}")
    print(f"[+] Human summary -> {summary_path}")
    print(f"\n    Keep the mapping JSON safe – it's the only way to reverse the anonymization.")


def main():
    parser = argparse.ArgumentParser(description="Anonymize sensitive data in K10 log bundles")
    parser.add_argument("input_dir", help="Path to extracted K10 log bundle")
    parser.add_argument("output_dir", help="Destination for anonymized logs")
    args = parser.parse_args()

    if not os.path.isdir(args.input_dir):
        print(f"Error: {args.input_dir} is not a directory")
        sys.exit(1)

    process_bundle(args.input_dir, args.output_dir)


if __name__ == "__main__":
    main()
