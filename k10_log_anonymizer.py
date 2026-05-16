#!/usr/bin/env python3
"""
K10 Log Bundle Anonymizer v3.3
==============================
Anonymizes sensitive infrastructure data from Kasten K10 support log bundles.

Architecture:
  - Single-read: text files cached between detection and replacement
  - Binary files detected and copied verbatim (not corrupted)
  - Split replacement: non-IP mega-regex + IP pattern + OIDC patterns
  - OIDC tokens handled by regex pattern (not literals) to avoid mega-regex
    explosion when thousands of unique state/code values are present
  - Keyword-gated detection for cheap patterns
  - Optional Aho-Corasick (pip install pyahocorasick) for large pattern sets
  - Optional verification pass (--verify) to detect leaks in output
  - Optional incremental mapping (--mapping-in) for cross-bundle consistency
  - Optional dry-run mode (--dry-run) to inspect mapping without writing

Usage:
  python3 k10_log_anonymizer.py <input_dir> <output_dir> [options]
"""

import argparse
import json
import logging
import os
import re
import shutil
import sys
import uuid
from collections import OrderedDict
from pathlib import Path

try:
    import ahocorasick
    HAS_AC = True
except ImportError:
    HAS_AC = False

logger = logging.getLogger("k10_anonymizer")

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
SAFE_DOMAIN_SUBSTRINGS = ("kasten.io", "openshift.io", "kubernetes.io",
                         # Anonymized output suffixes — prevent re-anonymization
                         # of already-redacted hosts on a second pass.
                         "example.internal", "anon-storage")

# Anonymized output namespaces — IPs in this range come from previous runs and
# must not be re-detected. Kept in sync with the IP formatter in build_replacer.
ANON_IP_PREFIX = "198.51."

# Binary detection: scan first BINARY_SNIFF_BYTES for NUL byte or non-UTF8 content
BINARY_SNIFF_BYTES = 4096

# Memory cap for text cache (warning only, does not abort)
CACHE_WARN_MB = 1024


# ---------------------------------------------------------------------------
# Mapping store
# ---------------------------------------------------------------------------

class MappingStore:
    """Stores original→anonymized mappings with stable, deterministic counters."""

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

    def load_existing(self, mapping_dict):
        """Load a pre-existing mapping (incremental mode)."""
        for category, entries in mapping_dict.items():
            self._maps[category] = OrderedDict(entries)
            # Counter restarts after the highest existing entry so new values
            # never collide with previously assigned anonymized labels
            self._counters[category] = len(entries)

    def dump(self):
        return {cat: dict(m) for cat, m in self._maps.items()}


# ---------------------------------------------------------------------------
# File classification (text vs binary)
# ---------------------------------------------------------------------------

def is_text_file(path: str, blocksize: int = BINARY_SNIFF_BYTES) -> bool:
    """Heuristic: read first blocksize bytes, reject if NUL present or not UTF-8."""
    try:
        with open(path, "rb") as f:
            chunk = f.read(blocksize)
    except OSError:
        return False
    if not chunk:
        return True  # empty file is safe to treat as text
    if b"\x00" in chunk:
        return False
    try:
        chunk.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

# Strict IP regex: each octet 0-255 (rejects 1.2.3.4 in version strings less often)
PAT_IP = re.compile(
    r'\b((?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d))\b'
)

# Generalized FQDN: *.apps.* (any TLD) + internal TLDs, stops at :, /, ", whitespace
PAT_DOM = re.compile(
    r'\b('
    r'[a-zA-Z0-9][-a-zA-Z0-9]*\.apps\.[a-zA-Z0-9][-a-zA-Z0-9.]*[a-zA-Z0-9]'
    r'|[a-zA-Z0-9][-a-zA-Z0-9]*\.(?:home|local|lab|corp|internal|lan)'
    r')(?=[:/"\s\'<>]|$)')
PAT_BDOM = re.compile(r'apps\.([a-zA-Z0-9][-a-zA-Z0-9.]*)\.([a-z]{2,})\b')
# OCP API endpoints: api.xxx.yyy.tld
PAT_API_FQDN = re.compile(r'\bapi\.([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-z]{2,})\b')

# S3 full URLs in Kopia HTTP debug logs (and similar contexts)
# Hostname allows letters, digits, dots and dashes (e.g. s3.us-east-1.amazonaws.com)
PAT_S3_URL = re.compile(
    r'https?://(s3[a-zA-Z0-9.\-]*\.[a-z]{2,}(?:\.[a-z]{2,})*)'
    r'/([a-zA-Z0-9][-a-zA-Z0-9_]*)(?=/)')


def detect_and_cache(input_dir: str) -> tuple[dict, list[tuple[str, str, str]], list[tuple[str, str]]]:
    """Scan input_dir, return (detected values, text file cache, binary file list).

    text cache: list of (abs_path, rel_path, content_str)
    binary list: list of (abs_path, rel_path) — copied verbatim, never anonymized
    """
    detected = {
        "cluster_uuids": set(), "cluster_names": set(), "domains": set(),
        "storage_endpoints": set(), "buckets": set(), "ips": set(),
        "namespaces": set(), "access_keys": set(),
        "oidc_codes": set(), "oidc_states": set(),
    }

    # Gated patterns: (keyword, regex, detected target)
    # Note: "cluster_name" keyword maps to cluster_uuids target because the value
    # captured is a UUID, not a name. The K10 schema uses cluster_name=<uuid>.
    gated = [
        ("cluster_name", re.compile(
            r'cluster_name["\s:=>]+["\s]*([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', re.I),
            "cluster_uuids"),
        ("namespace", re.compile(r'namespace[=":>]+\s*"?\s*([a-z0-9][-a-z0-9]*)'),
            "namespaces"),
        ("appName", re.compile(r'appName=([a-z0-9][-a-z0-9]*)'),
            "namespaces"),
        # Kubernetes API server paths: /api/v1/namespaces/<ns>/...
        # Catches namespaces that ONLY appear in URL paths (audit logs, raw
        # API traces, kube-apiserver dumps) and would otherwise never be
        # detected and therefore never anonymized.
        ("/namespaces/", re.compile(r'/namespaces/([a-z0-9][-a-z0-9]{0,62})(?=[/?"\s]|$)'),
            "namespaces"),
        ("bucket", re.compile(r'bucket[=":>]+\s*"?\s*([a-zA-Z0-9][-a-zA-Z0-9_.]*)'),
            "buckets"),
        ("endpoint", re.compile(r'endpoint[=":>]+\s*"?\s*"?(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9.]+\.[a-z]{2,})'),
            "storage_endpoints"),
        ("cluster", re.compile(r'cluster[=":>]+\s*"?\s*([a-zA-Z0-9][-a-zA-Z0-9_]*)"?'),
            "cluster_names"),
        ("accessKeyID", re.compile(r'accessKeyID["\s:=>]+["\s]*([a-zA-Z0-9]{20,})'),
            "access_keys"),
        # AWS SigV4 Credential= in Authorization headers
        ("Credential=", re.compile(r'Credential=([a-zA-Z0-9]{20,})/'),
            "access_keys"),
        # OIDC authorization codes
        ("code=", re.compile(r'[?&]code=([a-zA-Z0-9]{20,})'),
            "oidc_codes"),
        # OIDC state tokens
        ("oidc-auth-state", re.compile(r'state=(oidc-auth-state-[a-zA-Z0-9]+)'),
            "oidc_states"),
    ]

    text_cache = []
    binary_files = []
    skipped_count = 0
    total_text_bytes = 0

    for root, _, files in os.walk(input_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            rel = os.path.relpath(fpath, input_dir)

            if not is_text_file(fpath):
                binary_files.append((fpath, rel))
                continue

            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
            except Exception as e:
                logger.warning("Skipped %s during read: %s", rel, e)
                skipped_count += 1
                continue

            text_cache.append((fpath, rel, content))
            total_text_bytes += len(content)

            for m in PAT_IP.finditer(content):
                ip = m.group(1)
                if ip in IP_PASSTHROUGH:
                    continue
                # Skip IPs already in the anonymized output pool (idempotence)
                if ip.startswith(ANON_IP_PREFIX):
                    continue
                detected["ips"].add(ip)

            for m in PAT_DOM.finditer(content):
                dom = m.group(1).rstrip("/.")
                if dom not in SAFE_DOMAIN_PATTERNS and not any(s in dom for s in SAFE_DOMAIN_SUBSTRINGS):
                    detected["domains"].add(dom)
            for m in PAT_BDOM.finditer(content):
                dom = f"apps.{m.group(1)}.{m.group(2)}"
                if dom not in SAFE_DOMAIN_PATTERNS and not any(s in dom for s in SAFE_DOMAIN_SUBSTRINGS):
                    detected["domains"].add(dom)
                    # Extract OCP cluster short name from base domain
                    # e.g. apps.my-cluster.example.com -> my-cluster
                    cluster_part = m.group(1).split(".")[0]
                    if len(cluster_part) >= 3 and cluster_part not in ("apps", "api"):
                        detected["cluster_names"].add(cluster_part)

            for m in PAT_API_FQDN.finditer(content):
                full = f"api.{m.group(1)}"
                if not any(s in full for s in SAFE_DOMAIN_SUBSTRINGS):
                    detected["domains"].add(full)

            for m in PAT_S3_URL.finditer(content):
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
                        if (len(val) >= 2 and val not in KNOWN_SAFE_NAMESPACES
                                and not val.startswith(SAFE_NAMESPACE_PREFIXES)):
                            detected[target].add(val)
                    elif target == "storage_endpoints":
                        if not any(x in val for x in ["svc.cluster", "kasten.io", "kubernetes.io"]):
                            detected[target].add(val)
                    elif target == "cluster_names":
                        if len(val) < 20 and val not in ("true", "false", "live"):
                            detected[target].add(val)
                    elif target == "cluster_uuids":
                        # Skip UUIDs already in the anonymized output pool
                        # (00000000-0000-0000-abcd-efXXXXXXXXXX) for idempotence
                        v_lower = val.lower()
                        if v_lower.startswith("00000000-0000-0000-abcd-ef"):
                            continue
                        detected[target].add(v_lower)
                    else:
                        detected[target].add(val)

    total_mb = total_text_bytes / 1048576
    if total_mb > CACHE_WARN_MB:
        logger.warning("Text cache size %.0f MB exceeds soft limit (%d MB). "
                       "Consider splitting the bundle for very large inputs.",
                       total_mb, CACHE_WARN_MB)
    if skipped_count:
        logger.info("%d file(s) skipped during read", skipped_count)
    logger.info("Classified: %d text, %d binary file(s)",
                len(text_cache), len(binary_files))

    return ({k: sorted(v) for k, v in detected.items()}, text_cache, binary_files)


# ---------------------------------------------------------------------------
# Build replacer
# ---------------------------------------------------------------------------

def build_replacer(detected: dict, store: MappingStore | None = None):
    """Build the replacement function and return (replace_func, store)."""
    if store is None:
        store = MappingStore()
    non_ip_lookup = {}
    ip_lookup = {}
    short_ns_lookup = {}
    # UUIDs handled by regex (not literals) so all casings — lower, upper,
    # mixed — resolve to the same anonymized value via a case-insensitive
    # lookup. Storing each casing variant in the literal table would miss
    # mixed-case forms (e.g. "A1b2C3d4-...") that weren't pre-enumerated.
    uuid_lookup = {}

    for uid in detected.get("cluster_uuids", []):
        r = store.get_or_create("cluster_uuid", uid,
            lambda n: str(uuid.UUID(int=0xABCDEF0000000000 + n)))
        uuid_lookup[uid.lower()] = r

    # Track which literals are already claimed by a higher-priority category.
    # Priority order: domain > storage_endpoint > bucket > access_key >
    # namespace >= 4 chars > cluster_name.
    # This avoids the same string being mapped twice (e.g. an OCP api.* FQDN
    # captured by both the domain regex and the endpoint= gated pattern, or a
    # cluster short name appearing inside a longer FQDN already replaced).
    claimed: set[str] = set()

    for dom in sorted(detected.get("domains", []), key=len, reverse=True):
        r = store.get_or_create("domain", dom, lambda n: f"redacted-host{n:02d}.example.internal")
        non_ip_lookup[dom] = r
        claimed.add(dom)

    for ep in detected.get("storage_endpoints", []):
        if ep in claimed:
            logger.debug("Skipping storage_endpoint '%s' (already claimed as domain)", ep)
            continue
        r = store.get_or_create("storage_endpoint", ep, lambda n: f"s3.anon-storage{n:02d}.example.com")
        non_ip_lookup[ep] = r
        claimed.add(ep)

    for bkt in detected.get("buckets", []):
        if bkt in claimed:
            logger.debug("Skipping bucket '%s' (already claimed)", bkt)
            continue
        r = store.get_or_create("bucket_name", bkt, lambda n: f"anon-bucket-{n:03d}")
        non_ip_lookup[bkt] = r
        claimed.add(bkt)

    for ak in detected.get("access_keys", []):
        if ak in claimed:
            continue
        r = store.get_or_create("access_key", ak, lambda n: f"REDACTED_ACCESS_KEY_{n:03d}")
        non_ip_lookup[ak] = r
        claimed.add(ak)

    # Namespaces: >= 4 chars go in mega-regex, < 4 go contextual
    for ns in detected.get("namespaces", []):
        if ns in claimed:
            continue
        r = store.get_or_create("namespace", ns, lambda n: f"app-ns-{n:03d}")
        if len(ns) >= 4:
            non_ip_lookup[ns] = r
            claimed.add(ns)
        else:
            short_ns_lookup[ns] = r

    # Cluster names: short names (< 3 chars) skipped entirely.
    # Names < CLUSTER_NAME_LITERAL_MIN chars go to a contextual lookup (anchored
    # by cluster=, cluster_name=, or in /clusters/<name>/ paths) to avoid the
    # substring leak that would otherwise turn "production" into "cluster01uction"
    # when the cluster name happens to be a common English/French word fragment
    # like "prod", "dev", "qa", "test". Longer names (>=8) are still safe in the
    # literal mega-regex because the probability of collision with English/French
    # text drops sharply at that length.
    CLUSTER_NAME_LITERAL_MIN = 8
    short_cluster_lookup = {}
    for cn in detected.get("cluster_names", []):
        if len(cn) < 3:
            logger.debug("Skipping cluster_name '%s' (too short for safe replacement)", cn)
            continue
        if cn in claimed:
            logger.debug("Skipping cluster_name '%s' (already claimed)", cn)
            continue
        r = store.get_or_create("cluster_name", cn, lambda n: f"cluster{n:02d}")
        if len(cn) >= CLUSTER_NAME_LITERAL_MIN:
            non_ip_lookup[cn] = r
            claimed.add(cn)
        else:
            short_cluster_lookup[cn] = r

    # OIDC: pre-seed mapping, but replace by PATTERN not by literal
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

    # ---- Build non-IP literal matcher ----
    if HAS_AC and non_ip_lookup:
        automaton = ahocorasick.Automaton()
        for original, replacement in non_ip_lookup.items():
            automaton.add_word(original, (original, replacement))
        automaton.make_automaton()

        def replace_literals(text: str) -> str:
            # Collect all matches, then resolve overlaps:
            # at each starting position, prefer the LONGEST match (longest-leftmost)
            matches = []
            for end_idx, (original, replacement) in automaton.iter(text):
                start_idx = end_idx - len(original) + 1
                matches.append((start_idx, end_idx, replacement))
            # Sort by start asc, then by length desc (longest first at same start)
            matches.sort(key=lambda m: (m[0], -(m[1] - m[0])))

            result = []
            last_end = 0
            for start_idx, end_idx, replacement in matches:
                if start_idx >= last_end:
                    result.append(text[last_end:start_idx])
                    result.append(replacement)
                    last_end = end_idx + 1
                # Else: overlaps with a previous (longer or earlier) match — skip
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

    # IPs use the same strict pattern as detection for consistency
    ip_pattern = PAT_IP

    # UUID pattern: case-insensitive lookup so mixed-case UUIDs in logs
    # (e.g. "A1b2C3d4-...") resolve to the same anonymized value as their
    # canonical lowercase form. Pre-anonymized UUIDs (00000000-0000-0000-...)
    # are absent from uuid_lookup and pass through unchanged.
    uuid_pat = re.compile(
        r'\b([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b')

    # OIDC code pattern: replace code=xxx with dict lookup
    oidc_code_pat = re.compile(r'([?&]code=)([a-zA-Z0-9]{20,})')
    # OIDC state pattern: replace state=oidc-auth-state-xxx
    oidc_state_pat = re.compile(r'(state=)(oidc-auth-state-[a-zA-Z0-9]+)')

    # Short namespace contextual patterns
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

    # Short cluster_name contextual patterns: only replace at known anchors
    # to avoid substring leak in unrelated words.
    short_cluster_patterns = []
    for cn, replacement in short_cluster_lookup.items():
        escaped = re.escape(cn)
        short_cluster_patterns.append((
            re.compile(
                r'(cluster[=":>]+\s*"?)' + escaped + r'("?)(?=[\s,;}"\']|$)'
                r'|(cluster_name[=":>]+\s*"?)' + escaped + r'("?)(?=[\s,;}"\']|$)'
                r'|(/clusters/)' + escaped + r'(?=[/?"\s]|$)'
            ),
            cn, replacement
        ))

    def replace_content(text: str) -> str:
        # Pass 1: non-IP literals (domains, endpoints, keys, ns>=4, buckets,
        # cluster_names >= 8 chars)
        text = replace_literals(text)
        # Pass 2: UUIDs (case-insensitive regex lookup)
        if uuid_lookup:
            text = uuid_pat.sub(
                lambda m: uuid_lookup.get(m.group(1).lower(), m.group(1)), text)
        # Pass 3: IPs
        text = ip_pattern.sub(lambda m: ip_lookup.get(m.group(0), m.group(0)), text)
        # Pass 4: OIDC codes (pattern-based, dict lookup)
        if oidc_code_map:
            text = oidc_code_pat.sub(
                lambda m: m.group(1) + oidc_code_map.get(m.group(2), m.group(2)), text)
        # Pass 5: OIDC states (pattern-based, dict lookup)
        if oidc_state_map:
            text = oidc_state_pat.sub(
                lambda m: m.group(1) + oidc_state_map.get(m.group(2), m.group(2)), text)
        # Pass 6: short namespaces (contextual only)
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
        # Pass 7: short cluster_names (contextual only, prevents substring leak)
        for pat, cn, replacement in short_cluster_patterns:
            def _sub_c(m, _r=replacement):
                if m.group(1) is not None:
                    return m.group(1) + _r + (m.group(2) or "")
                elif m.group(3) is not None:
                    return m.group(3) + _r + (m.group(4) or "")
                elif m.group(5) is not None:
                    return m.group(5) + _r
                return m.group(0)
            text = pat.sub(_sub_c, text)
        return text

    return replace_content, store


# ---------------------------------------------------------------------------
# Verification pass
# ---------------------------------------------------------------------------

# Patterns considered indicators of remaining sensitive data in output.
# Each is checked against the anonymized files; matches whose value falls in
# the anonymized output space (e.g. "redacted-host01.example.internal",
# "198.51.x.y") are filtered out.
VERIFY_PATTERNS = {
    "ip_remaining": PAT_IP,
    "fqdn_remaining": PAT_DOM,
    "s3_url_remaining": PAT_S3_URL,
    "oidc_code_remaining": re.compile(r'[?&]code=([a-zA-Z0-9]{20,})'),
    "oidc_state_remaining": re.compile(r'state=(oidc-auth-state-(?!redacted-)[a-zA-Z0-9]+)'),
    "credential_remaining": re.compile(r'Credential=(?!REDACTED_)([a-zA-Z0-9]{20,})/'),
}

ANON_HOST_SUFFIX = "example.internal"
ANON_S3_SUFFIX = "anon-storage"
ANON_CODE_PREFIX = "REDACTED_OIDC_CODE_"


def verify_output(output_dir: str, max_examples: int = 5) -> dict[str, list[str]]:
    """Re-scan the anonymized output for any sensitive patterns that slipped through."""
    findings: dict[str, list[str]] = {}
    for root, _, files in os.walk(output_dir):
        for fname in files:
            if fname.startswith("_anonymization_"):
                continue
            fpath = os.path.join(root, fname)
            rel = os.path.relpath(fpath, output_dir)
            if not is_text_file(fpath):
                continue
            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
            except Exception:
                continue

            for label, pattern in VERIFY_PATTERNS.items():
                for m in pattern.finditer(content):
                    val = m.group(1) if m.groups() else m.group(0)
                    # Filter values that are already in the anonymized output space
                    if label == "ip_remaining":
                        if val in IP_PASSTHROUGH or val.startswith(ANON_IP_PREFIX):
                            continue
                    elif label == "fqdn_remaining":
                        if ANON_HOST_SUFFIX in val or any(s in val for s in SAFE_DOMAIN_SUBSTRINGS):
                            continue
                    elif label == "s3_url_remaining":
                        if ANON_S3_SUFFIX in val:
                            continue
                    elif label == "oidc_code_remaining":
                        if val.startswith(ANON_CODE_PREFIX):
                            continue

                    findings.setdefault(label, []).append(f"{rel}: {val}")
                    if len(findings[label]) >= max_examples:
                        break
    return findings


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def process_bundle(input_dir: str, output_dir: str,
                   mapping_in: str | None = None,
                   dry_run: bool = False,
                   verify: bool = False):
    import time
    t0 = time.time()

    logger.info("Scanning %s (single-read with caching)...", input_dir)
    detected, text_cache, binary_files = detect_and_cache(input_dir)
    t_detect = time.time()

    total_bytes = sum(len(c) for _, _, c in text_cache)
    total_mb = total_bytes / 1048576
    logger.info("Cached %d text files (%.1f MB) + %d binary file(s) in %.2fs",
                len(text_cache), total_mb, len(binary_files), t_detect - t0)

    logger.info("Detected values to anonymize:")
    total_patterns = 0
    for cat, values in detected.items():
        logger.info("  %s: %d unique value(s)", cat, len(values))
        total_patterns += len(values)
        for v in values[:3]:
            logger.info("    - %s", v)
        if len(values) > 3:
            logger.info("    ... and %d more", len(values) - 3)

    # Optional: load incremental mapping
    store = MappingStore()
    if mapping_in:
        if not os.path.isfile(mapping_in):
            logger.error("Mapping file not found: %s", mapping_in)
            sys.exit(2)
        with open(mapping_in, "r", encoding="utf-8") as f:
            existing = json.load(f)
        store.load_existing(existing)
        logger.info("Loaded incremental mapping from %s (%d categories)",
                    mapping_in, len(existing))

    replace_func, store = build_replacer(detected, store=store)
    t_build = time.time()

    n_ip = len(detected.get("ips", []))
    backend = "Aho-Corasick" if HAS_AC else "mega-regex"
    logger.info("Replacement backend: %s + IP pattern (%d) + OIDC patterns + short-ns patterns",
                backend, n_ip)

    if dry_run:
        # Print what WOULD be done, write nothing except mapping summary
        os.makedirs(output_dir, exist_ok=True)
        mapping = store.dump()
        summary_path = os.path.join(output_dir, "_anonymization_summary.txt")
        _write_summary(summary_path, mapping)
        logger.info("[DRY-RUN] Summary written to %s — no files anonymized", summary_path)
        return

    os.makedirs(output_dir, exist_ok=True)

    # Copy binary files verbatim
    binary_copied = 0
    for src, rel in binary_files:
        dst = os.path.join(output_dir, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        try:
            shutil.copy2(src, dst)
            binary_copied += 1
        except Exception as e:
            logger.warning("Failed to copy binary %s: %s", rel, e)

    # Anonymize text files
    file_count = 0
    for _, rel, content in text_cache:
        dst = os.path.join(output_dir, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        try:
            result = replace_func(content)
            with open(dst, "w", encoding="utf-8") as f:
                f.write(result)
            file_count += 1
        except Exception as e:
            logger.warning("Skipped %s during write: %s", rel, e)
    t_replace = time.time()

    # Write mapping artifacts
    mapping_path = os.path.join(output_dir, "_anonymization_mapping.json")
    mapping = store.dump()
    with open(mapping_path, "w", encoding="utf-8") as f:
        json.dump(mapping, f, indent=2)

    summary_path = os.path.join(output_dir, "_anonymization_summary.txt")
    _write_summary(summary_path, mapping)

    t_end = time.time()
    rate = total_mb / (t_end - t0) if (t_end - t0) > 0 else 0

    logger.info("Anonymized %d text file(s) + copied %d binary file(s) -> %s/",
                file_count, binary_copied, output_dir)
    logger.info("Mapping table -> %s", mapping_path)
    logger.info("Timing: detect %.2fs + build %.2fs + replace+write %.2fs = %.2fs total",
                t_detect-t0, t_build-t_detect, t_end-t_build, t_end-t0)
    logger.info("Throughput: %.1f MB/s (%d patterns)", rate, total_patterns)
    logger.warning("Keep the mapping JSON safe — it is the only way to reverse the anonymization.")

    # Optional verification pass
    if verify:
        logger.info("Running verification pass on %s ...", output_dir)
        findings = verify_output(output_dir)
        if findings:
            logger.warning("Verification found potential leaks:")
            for label, examples in findings.items():
                logger.warning("  [%s] %d sample(s):", label, len(examples))
                for ex in examples:
                    logger.warning("    %s", ex)
        else:
            logger.info("Verification clean: no sensitive patterns detected in output.")


def _write_summary(path: str, mapping: dict):
    """Write the human-readable summary file."""
    with open(path, "w", encoding="utf-8") as f:
        f.write("K10 Log Bundle Anonymization Summary\n")
        f.write("=" * 50 + "\n\n")
        for cat, entries in mapping.items():
            f.write(f"[{cat}] ({len(entries)} entries)\n")
            f.write("-" * 40 + "\n")
            items = list(entries.items())
            # Show up to 50 inline, then truncate; truncation message uses
            # the actual shown count so the math is consistent.
            shown = min(50, len(items))
            for orig, anon in items[:shown]:
                f.write(f"  {orig:<60s} -> {anon}\n")
            if len(items) > shown:
                f.write(f"  ... ({len(items) - shown} more entries, see JSON for full list)\n")
            f.write("\n")


def main():
    parser = argparse.ArgumentParser(
        description="Anonymize Kasten K10 log bundles for safe external sharing.")
    parser.add_argument("input_dir", help="Path to extracted K10 log bundle")
    parser.add_argument("output_dir", help="Destination for anonymized logs")
    parser.add_argument("--mapping-in", metavar="FILE",
                        help="Pre-existing mapping JSON to extend (cross-bundle consistency)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Detect and print mapping without writing anonymized files")
    parser.add_argument("--verify", action="store_true",
                        help="Re-scan output and warn on remaining sensitive patterns")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output (DEBUG level)")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Quiet output (WARNING level and above)")
    args = parser.parse_args()

    level = logging.INFO
    if args.verbose:
        level = logging.DEBUG
    elif args.quiet:
        level = logging.WARNING
    logging.basicConfig(level=level, format="[%(levelname)s] %(message)s")

    if not os.path.isdir(args.input_dir):
        logger.error("%s is not a directory", args.input_dir)
        sys.exit(1)

    process_bundle(args.input_dir, args.output_dir,
                   mapping_in=args.mapping_in,
                   dry_run=args.dry_run,
                   verify=args.verify)


if __name__ == "__main__":
    main()
