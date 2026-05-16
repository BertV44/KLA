# K10 Log Bundle Anonymizer

A Python utility that anonymizes sensitive infrastructure data from **Kasten K10** support log bundles, making them safe to share externally (e.g. with vendor support) while preserving log structure and debuggability.

## Why

K10's built-in log collector (`k10tools`) does a good job masking secret values, but the resulting bundle still contains infrastructure fingerprinting data: cluster identity, internal IPs, storage targets, FQDNs, and customer workload namespaces. This script replaces those with consistent, deterministic fake values and produces a **reversible mapping table** so the original data can be recovered internally if needed.

This is a community tool. Anyone working with K10 support bundles — operators, partners, customers — can use it before sharing logs outside their organization.

## What gets anonymized

| # | Category | Example (before → after) |
|---|----------|--------------------------|
| 1 | **Cluster identity** – UUIDs and short names | `a1b2c3d4-e5f6-…` → `00000000-…-ef0000000001`, `my-ocp-cluster` → `cluster01` |
| 2 | **FQDNs / OpenShift routes** – any TLD | `kasten.apps.my-ocp-cluster.example.com` → `redacted-host02.example.internal` |
| 3 | **Object storage** – endpoints (incl. regional S3), buckets, S3 access keys | `s3.us-east-1.amazonaws.com` → `s3.anon-storage01.example.com` |
| 4 | **IP addresses** – pod IPs, ClusterIPs, node IPs | `10.131.2.45` → `198.51.0.21` |
| 5 | **Customer workload namespaces** – all lengths | `my-app-staging` → `app-ns-005`, `dev` → `app-ns-001` |
| 6 | **Kopia debug logs** – S3 URLs, AWS SigV4 Credential= | `Credential=ABCD1234…/date/region/s3/…` → `Credential=REDACTED_ACCESS_KEY_002/…` |
| 7 | **OIDC auth tokens** – authorization codes and state params | `code=xyzabc123…` → `code=REDACTED_OIDC_CODE_0013` |

Standard OpenShift (`openshift-*`) and K10 (`kasten-io`) namespaces are **preserved** so logs remain useful for troubleshooting. Binary files in the bundle are **copied byte-for-byte without modification**.

## Requirements

- Python 3.10+
- No external dependencies (stdlib only)
- Optional: `pyahocorasick` for faster literal matching on large pattern sets (see [Aho-Corasick acceleration](#optional-aho-corasick-acceleration))

## Quick start

```bash
# 1. Extract the K10 log bundle
unzip k10logs.zip -d k10logs

# 2. Run the anonymizer
python3 k10_log_anonymizer.py k10logs/k10logs anonymized_logs

# 3. Review the output
cat anonymized_logs/_anonymization_summary.txt
```

## Usage

```
python3 k10_log_anonymizer.py <input_dir> <output_dir> [options]
```

| Option | Description |
|--------|-------------|
| `input_dir` | Path to the extracted K10 log bundle directory |
| `output_dir` | Destination for the anonymized copy (created if missing) |
| `--mapping-in FILE` | Reuse an existing mapping JSON for cross-bundle consistency |
| `--dry-run` | Detect and write the mapping summary without anonymizing files |
| `--verify` | After anonymization, re-scan the output and warn on remaining sensitive patterns |
| `-v`, `--verbose` | Verbose output (DEBUG level) |
| `-q`, `--quiet` | Quiet output (WARNING level and above) |

### Common workflows

**Validate detection before producing output:**

```bash
python3 k10_log_anonymizer.py k10logs/ /tmp/preview --dry-run
cat /tmp/preview/_anonymization_summary.txt
```

**Anonymize with post-anonymization verification:**

```bash
python3 k10_log_anonymizer.py k10logs/ anonymized_logs/ --verify
```

**Process multiple bundles from the same cluster with consistent mapping:**

```bash
# First bundle establishes the mapping
python3 k10_log_anonymizer.py bundle_day1/ out_day1/

# Subsequent bundles reuse it so the same IP, namespace, etc. map identically
python3 k10_log_anonymizer.py bundle_day2/ out_day2/ \
    --mapping-in out_day1/_anonymization_mapping.json

python3 k10_log_anonymizer.py bundle_day3/ out_day3/ \
    --mapping-in out_day2/_anonymization_mapping.json
```

## Output structure

```
anonymized_logs/
├── _anonymization_mapping.json   # Machine-readable mapping (keep safe!)
├── _anonymization_summary.txt    # Human-readable mapping overview
├── k10_debug_logs.txt            # Anonymized debug logs
└── services/
    ├── auth-svc-xxxxx.txt
    ├── catalog-svc-xxxxx.txt
    ├── crypto-svc-xxxxx.txt
    ├── ...
    └── gateway-xxxxx.txt
```

### Mapping table

The `_anonymization_mapping.json` file is the **only way to reverse the anonymization**. Keep it in a secure, internal location — do not share it alongside the anonymized logs.

Structure:

```json
{
  "cluster_uuid": {
    "a1b2c3d4-e5f6-7890-abcd-ef1234567890": "00000000-0000-0000-abcd-ef0000000001"
  },
  "cluster_name": {
    "my-ocp-cluster": "cluster01"
  },
  "ip_address": {
    "10.131.2.45": "198.51.0.21",
    "172.30.99.10": "198.51.0.4"
  }
}
```

## Performance

Benchmarked on two real-world bundles:

| Bundle | Size | Files | Patterns | Time | Throughput |
|--------|------|-------|----------|------|------------|
| Small (S3-compatible storage, 65 patterns) | 95 MB | 22 | 65 | 8.8s | 10.9 MB/s |
| Large (OIDC+Kopia debug, 2919 patterns) | 285 MB | 44 | 2919 | 74s | 3.8 MB/s |

The throughput difference reflects the OIDC token volume: the larger bundle had 2500+ unique OIDC state tokens and 45+ auth codes, handled by dedicated regex passes. The core mega-regex stays small (~90 literals).

### How it works under the hood

The script runs in two phases: **detection** (scan all files to discover sensitive values) and **replacement** (substitute them with anonymized equivalents).

**File classification** happens first: each file is sniffed (first 4 KB) for NUL bytes or invalid UTF-8. Binary files are copied verbatim to the output and never anonymized; only text files enter the detection pipeline.

**Detection** accounts for ~63% of total time on text files. Files are read once and cached in memory for reuse during replacement. Detection patterns are split into two groups: "always-scan" patterns (IPs and domains, which have no cheap keyword trigger) and "keyword-gated" patterns (namespace, bucket, endpoint, cluster, accessKeyID) that only run on files containing the relevant keyword.

**Replacement** uses a multi-pass strategy, each pass optimized for its data type:

1. **Non-IP literals** (domains, endpoints, access keys, namespaces ≥ 4 chars, bucket names, cluster names ≥ 8 chars) — single compiled alternation regex or Aho-Corasick trie, with dict callback.
2. **Cluster UUIDs** — dedicated regex pass with case-insensitive dict lookup. UUIDs are handled by regex rather than as literals so that mixed-case forms (`A1b2C3d4-...`) resolve to the same anonymized value as their canonical lowercase form without requiring every casing variant to be pre-enumerated in the literal table.
3. **IP addresses** — single octet-bounded pattern (each octet 0–255) with dict lookup. Separate from literals because a pattern-based approach is 46% faster than 300+ IP alternations.
4. **OIDC codes and states** — dedicated regex patterns (`code=xxx`, `state=oidc-auth-state-xxx`) with dict callback. Kept separate from the mega-regex to avoid performance degradation when thousands of unique tokens are present.
5. **Short namespaces** (< 4 chars) — contextual regex that only replaces in known patterns (`namespace=`, `appName=`, `/namespaces/`, `"namespace"=>`), avoiding false positives from substring matches.
6. **Short cluster names** (< 8 chars) — contextual regex anchored on `cluster=`, `cluster_name=`, and `/clusters/<name>/`. Necessary because common cluster names like `prod`, `dev`, `qa` would otherwise produce substring leaks inside unrelated words (e.g. `production` → `cluster01uction`). Longer names remain in the mega-regex where collision probability is negligible.

**Cross-category collision avoidance**: a value detected in multiple categories (e.g. an OCP `api.*` FQDN matched both as a domain and as a `storage_endpoint`) is claimed by the highest-priority category only. Priority order: `domain > storage_endpoint > bucket > access_key > namespace ≥ 4 > cluster_name`. This prevents the same string from receiving two different anonymized values across passes.

### Optional: Aho-Corasick acceleration

If `pyahocorasick` is installed (`pip install pyahocorasick`), the script automatically uses it for the non-IP literal matching pass. This replaces the regex alternation with an O(text_length) trie automaton, which scales better when the number of patterns grows into the hundreds (large multi-cluster environments with many namespaces, domains, and endpoints).

Matches reported by Aho-Corasick are resolved with **longest-leftmost** semantics: when two patterns overlap (e.g. `my-cluster` and `kasten.apps.my-cluster.example.com` both match starting at the same region of text), the longer match wins. Without this resolution step, the trie would emit matches in end-position order and short patterns finishing earlier could displace longer ones, producing partial substitutions like `kasten.apps.cluster01.example.com`.

For bundles with fewer than ~50 non-IP patterns, the built-in mega-regex (which is implicitly longest-first thanks to length-descending alternation) is already efficient and Aho-Corasick is not required.

### Going further: Rust/PyO3

For extreme throughput requirements (multi-GB bundles, automated pipelines processing dozens of bundles per day), the detection and replacement hot paths can be rewritten in Rust using PyO3. The Rust `aho_corasick` and `regex` crates (the same ones behind `ripgrep`) provide SIMD-accelerated matching that can reach 50–100 MB/s. The Python script would import the compiled Rust module as a drop-in replacement, with automatic fallback to pure Python if the Rust extension is not installed.

## Design decisions

**Consistency** — The same original value always produces the same anonymized value across all log files. If an IP appears in both `gateway` and `executor-svc` logs, it maps to the same anonymized IP in both. With `--mapping-in`, consistency also extends **across bundles**.

**Single-read architecture** — Every text file is read once during detection, cached in memory, then reused for replacement. This eliminates the double I/O cost of scanning then re-reading. Binary files are detected up front and bypass the cache entirely.

**Binary preservation** — Files containing NUL bytes or invalid UTF-8 in the first 4 KB are classified as binary and copied verbatim via `shutil.copy2`, preserving content and metadata. Previous versions opened all files with `errors="replace"`, which silently corrupted non-UTF8 bytes in binary content.

**Idempotence** — Running the anonymizer on its own output is a no-op. Detection filters out the anonymized output pool itself: `example.internal`, `anon-storage*`, the `198.51.0.0/24` IP range, and the `00000000-0000-0000-abcd-ef...` UUID range are skipped at detection time. This guards against accidental double-passes in pipelines and makes `--mapping-in` chains safe.

**Strict IP validation** — The IP regex enforces each octet to be 0–255, reducing false positives from version strings, build numbers, or hash fragments that happen to look like dotted quads.

**IP range choice** — Anonymized IPs use `198.51.0.0/24` (RFC 5737 TEST-NET-2), a range explicitly reserved for documentation and examples that will never collide with real infrastructure.

**Multi-format support** — K10 logs mix several formats and the replacer handles all of them: standard JSON (`"cluster_name":"a1b2c3d4-…"`), Fluentd/Ruby (`"namespace"=>"my-app"`), Prometheus labels (`bucket="my-bucket"`), freetext (Kopia `description` strings, URL query params like `cl=my-cluster` or `appName=dev`), Kubernetes API paths (`/api/v1/namespaces/<ns>/...` as seen in audit logs and raw apiserver dumps), Kopia HTTP debug dumps (full S3 request URLs with `Authorization: AWS4-HMAC-SHA256 Credential=…`), and OIDC redirect URLs (`code=xxx&state=oidc-auth-state-xxx`).

**Safe-list approach** — Platform namespaces (`openshift-*`, `kube-*`, `kasten-io`) and K8s/OCP API groups are explicitly preserved. Only customer-specific namespaces get anonymized.

**No K8s secrets in scope** — The script does not target K8s Secret values (they're already masked by K10's collector as `<set to the key ... in secret ...>`). It does catch: S3 access key IDs from both `accessKeyID=` fields and AWS SigV4 `Credential=` headers in Kopia HTTP debug logs, and OIDC authorization codes and state tokens from gateway redirect URLs.

## Verification

The `--verify` flag re-scans the output directory after anonymization and reports any sensitive patterns that may have slipped through. It checks for:

- IP addresses outside the anonymized range (`198.51.0.0/24`)
- FQDN patterns that don't end with `example.internal` and aren't in the safe-list
- S3 URLs that don't point to `anon-storage*`
- OIDC `code=` and `state=` values that aren't already redacted
- AWS SigV4 `Credential=` values that aren't already redacted

This is a useful safety net for high-confidence delivery to external recipients. A clean verify pass is not a formal proof of completeness, but it catches the common gaps.

## Tests

A unit test suite is included:

```bash
python3 -m unittest test_anonymizer.py -v
```

The suite (27 tests) covers binary file classification, mapping consistency, the longest-match overlap resolution, OIDC handling, AWS SigV4 detection, S3 URL detection with regional hostnames, safe-namespace preservation, and the verification pass. A dedicated `TestRegressionsV33` class guards against the four v3.3 fixes regressing: short cluster_name word boundary (`prod` must not corrupt `production`), namespace visible only in `/namespaces/<ns>/` API paths, mixed-case UUID detection, and double-pass idempotence.

## Customization

The script has configuration constants at the top of the file that can be adjusted per environment:

| Constant | Purpose |
|----------|---------|
| `KNOWN_SAFE_NAMESPACES` | Namespaces that should never be anonymized |
| `SAFE_NAMESPACE_PREFIXES` | Namespace prefixes to preserve (e.g. `openshift-`) |
| `IP_PASSTHROUGH` | IPs to skip (loopback, unspecified) |
| `SAFE_DOMAIN_PATTERNS` | FQDNs that are API groups, not infrastructure |
| `SAFE_DOMAIN_SUBSTRINGS` | Domain substrings to always preserve (also includes anonymized output suffixes for idempotence) |
| `ANON_IP_PREFIX` | Prefix of the anonymized IP pool; filtered out at detection to guarantee idempotence |
| `BINARY_SNIFF_BYTES` | Bytes to inspect when classifying text vs binary |
| `CACHE_WARN_MB` | Soft warning threshold for in-memory text cache size |
| `CLUSTER_NAME_LITERAL_MIN` | Minimum cluster_name length to enter the literal mega-regex; shorter names use contextual matching (defined inside `build_replacer`) |

### Adding new detection patterns

To anonymize additional categories:

1. Add a new `set()` in `detect_and_cache()` with the appropriate regex — if the pattern has a keyword anchor (e.g. `vaultAddr`), add it to the gated patterns list for efficiency.
2. In `build_replacer()`, decide the replacement strategy:
   - **Literal** (few unique values, low collision risk, e.g. long hostnames): add to `non_ip_lookup` → goes into the mega-regex.
   - **Pattern-based** (many unique values, e.g. session IDs, or any value where casing must be normalized like UUIDs): add a dedicated regex pass in `replace_content()` with dict callback.
   - **Contextual** (short values, high false-positive risk because the value may match unrelated words): add to a separate contextual replacement like `short_ns_patterns` or `short_cluster_patterns`. Anchor on explicit key=value patterns and URL paths only.

The literal threshold for cluster names is governed by `CLUSTER_NAME_LITERAL_MIN` (default 8). Adjust if your environment uses longer or shorter cluster naming conventions that could collide with common log vocabulary.

## Limitations

- **Pod and container names** are not anonymized (they contain K10 component names, not customer data).
- **Timestamps** are preserved as-is (needed for log correlation).
- **K8s resource UUIDs** (action IDs, manifest IDs) are not anonymized — only the cluster UUID is. This is intentional: action UUIDs are needed for troubleshooting and are not externally meaningful.
- **Secret checksums** (e.g. `checksum/secret: abc123…`) are left in place. They are SHA hashes of the secret content, not the secret itself, and are useful for verifying that all pods share the same secret version.
- **Memory cap** — the text cache lives in memory. A soft warning fires above 1 GB; for multi-GB bundles, consider splitting the input directory before running.

### Coverage gaps (not currently anonymized)

These categories are out of scope for the current version. Review your bundle manually if any apply:

- **IPv6 addresses** — only IPv4 is detected. Pod/node IPv6 addresses (e.g. `fe80::1234:5678`, `2001:db8::1`) pass through unchanged.
- **Bearer tokens and JWTs** in `Authorization:` headers (e.g. `Bearer eyJ...`). Only AWS SigV4 `Credential=` and OIDC `code=`/`state=` are handled.
- **Service account tokens** (`kubernetes.io/serviceaccount/token` values).
- **Email addresses and OIDC claim values** (`preferred_username`, `email`) emitted by Dex/auth-svc.
- **Bare node hostnames** without an FQDN suffix (e.g. `worker-node-01` standalone, not part of a full domain).
- **PVC, PV, and StorageClass names** when they encode customer or application identifiers.
- **Inline certificates** (`-----BEGIN CERTIFICATE-----` blocks); the CN and SAN fields they carry may be identifying.

## Changelog

### v3.3 — Anonymization completeness, substring leak fixes, idempotence

> v3.2 and v3.3 are released as a single consolidated commit (v3.2 was never pushed). The combined entry covers all changes since v3.1.

**Bug fix — substring leak on short cluster names.** Cluster names like `prod`, `dev`, `qa`, or `test` were placed in the literal mega-regex without word boundaries, so they matched inside unrelated words. A cluster named `prod` corrupted `production` into `cluster01uction` and `reproduce` into `recluster01uce`. The corruption was silent and partially hid the cluster name fragment inside other words, defeating the anonymization. v3.3 introduces a length threshold `CLUSTER_NAME_LITERAL_MIN` (default 8): shorter names go through a contextual pattern that only matches at explicit anchors (`cluster=`, `cluster_name=`, `/clusters/<name>/`). Longer names remain in the mega-regex where collision probability is negligible.

**Bug fix — namespace invisible in Kubernetes API URL paths.** Namespaces that only appeared as `/api/v1/namespaces/<ns>/...` (kube-apiserver audit logs, raw API traces, `oc get --raw` dumps) were never detected and therefore never anonymized. A namespace mentioned elsewhere in the bundle was caught and then propagated to URL paths by the literal pass, but a namespace exclusive to URL paths leaked. v3.3 adds a gated detection pattern keyed on `/namespaces/` with a lookahead-bounded capture.

**Bug fix — UUIDs in mixed case not anonymized.** The literal table was pre-populated with only the lowercase and uppercase forms of each detected UUID, missing every other casing variant. A UUID written as `A1b2C3d4-E5f6-...` (as commonly seen in logs that downcase only some components) passed through unchanged. v3.3 removes UUIDs from the literal table and handles them in a dedicated regex pass with case-insensitive dict lookup, so all casings resolve to the same anonymized value.

**Bug fix — pipeline was not idempotent.** Running the anonymizer twice on the same input corrupted previously-anonymized hosts: `redacted-host01.example.internal` became `redacted-host01.redacted-host01.example.internal` because `.internal` was matched as an internal TLD on the second pass. Similarly, anonymized IPs in `198.51.0.0/24` were re-detected and re-anonymized. v3.3 filters out the anonymized output pool itself at detection time (not just at the optional verification pass): `example.internal`, `anon-storage*`, the `198.51.0.0/24` range, and the `00000000-0000-0000-abcd-ef...` UUID range are skipped.

**Pipeline change.** `replace_content` grows from 5 to 7 passes:
- New pass 2: UUID regex with case-insensitive dict lookup.
- New pass 7: short cluster_name contextual patterns.
Pass ordering is documented inline. Existing pass semantics are unchanged.

**New regression tests.** The test suite grows from 23 to 27 tests with a dedicated `TestRegressionsV33` class:
- `test_short_cluster_name_word_boundary` — `prod` must not match inside `production`/`reproduce`.
- `test_namespace_only_in_url_path` — namespace exclusive to `/namespaces/<ns>/` is detected.
- `test_mixed_case_uuid_replaced` — all casings map to the same anonymized UUID.
- `test_double_pass_is_stable` — second pass on anonymized output is a no-op (output identical, mapping empty).

### v3.2 — Correctness fixes and quality-of-life features

**Bug fix — binary files were silently corrupted.** Previous versions opened every file with `errors="replace"`, which replaces invalid UTF-8 bytes with U+FFFD and writes the result as text. Any binary content (DER certs, archives, dumps) in the bundle was therefore corrupted in the output. v3.2 sniffs the first 4 KB of each file for NUL bytes or invalid UTF-8 and routes binary content through `shutil.copy2` so it is preserved byte-for-byte.

**Bug fix — overlapping matches in Aho-Corasick mode.** When a short literal (e.g. cluster short name `my-cluster`) and a longer one (`kasten.apps.my-cluster.example.com`) both matched in the same region, the Aho-Corasick automaton emitted them in end-position order. The first-match-wins greedy pass could pick the shorter one, leaving partial substitutions like `kasten.apps.cluster01.example.com`. v3.2 collects all matches, sorts them by start position then by length descending, and applies longest-leftmost resolution. The mega-regex fallback was already correct (alternation is length-descending) but is now consistent with the AC path.

**Bug fix — S3 URLs with regional hostnames were missed.** The detection regex `s3[a-zA-Z0-9.]*\.[a-z]{2,}` did not allow dashes in the hostname, so `s3.us-east-1.amazonaws.com` and similar regional endpoints in Kopia HTTP debug logs were never detected. The character class now includes `-`.

**Bug fix — cross-category collision.** A value captured by two detection paths (e.g. an OCP `api.*` FQDN, captured both by the domain regex and by the `endpoint=` gated pattern) was inserted twice into the literal lookup and could receive an unstable replacement. v3.2 introduces a `claimed` set with explicit priority: `domain > storage_endpoint > bucket > access_key > namespace ≥ 4 > cluster_name`.

**Bug fix — IP false positives.** The IP regex now bounds each octet to 0–255 instead of accepting any 1–3 digit sequence, reducing false positives from version strings and decimal hash fragments.

**Bug fix — cluster names too short to replace.** Names shorter than 3 characters were added to the mapping but never replaced in the output, producing misleading mapping entries. They are now skipped at detection time.

**Bug fix — summary truncation arithmetic.** Previous versions showed up to 10 items when entries exceeded 50, with the "X more entries" count referring to 50, not 10. The summary writer now shows up to 50 inline and reports the remaining count based on what was actually shown.

**New — `--dry-run` mode.** Runs detection and writes the mapping summary without producing anonymized output files. Useful for validating detection coverage on a sensitive bundle before committing to a full anonymization pass.

**New — `--verify` mode.** After anonymization, re-scans the output for sensitive patterns that weren't replaced. A clean verify pass is a useful safety net before sharing externally.

**New — `--mapping-in` for incremental processing.** Reuses an existing mapping JSON, guaranteeing that values appearing in multiple bundles (e.g. successive support snapshots from the same cluster) receive identical anonymized labels across runs.

**New — structured logging.** `print()` calls replaced with the `logging` module. `-v` and `-q` flags adjust verbosity.

**New — basic test suite.** `test_anonymizer.py` covers binary classification, mapping consistency, longest-match resolution, OIDC handling, AWS SigV4, S3 URLs with regional hostnames, safe namespaces, and the verify pass.

**Internal — `MappingStore.load_existing`.** Restores counters past the highest existing index so new values cannot collide with previously assigned labels.

### v3.1 — Gap fixes from second bundle analysis

Validated against two bundles of different sizes and configurations (different storage providers, authentication modes, and namespace counts).

**Gap 1 — FQDN detection generalized to any TLD.** The original regex only matched `.home`, `.local`, `.lab`, `.corp`, `.internal`, `.lan`. Environments using other public TLDs were missed. Fixed by generalizing the `apps.*` pattern to match any TLD, and adding detection for `api.xxx` OCP API server FQDNs.

**Gap 2 — S3 endpoints in Kopia HTTP debug logs.** Kopia debug files (`kopia_debug_files/*.log`) contain full HTTP request dumps with S3 URLs like `https://s3.region.provider.net/bucket-name/path`. The original script only detected endpoints from `endpoint="…"` key-value patterns. Added a dedicated URL-based S3 endpoint and bucket detection regex.

**Gap 3 — AWS SigV4 Credential= in Authorization headers.** Kopia HTTP logs also include `Authorization: AWS4-HMAC-SHA256 Credential=ACCESS_KEY/date/region/s3/aws4_request`. The access key in this format was not caught by `accessKeyID=` patterns. Added `Credential=([a-zA-Z0-9]{20,})/` detection.

**Gap 4 — OIDC authorization codes.** OIDC redirect URLs in gateway logs contain authorization codes (`code=abc123def456…`) that are potentially replayable. Added pattern-based detection and replacement.

**Gap 5 — OIDC state tokens.** Hundreds to thousands of `state=oidc-auth-state-xxx` values appear in auth flows. To avoid mega-regex explosion (thousands of literals would kill performance), OIDC codes and states are handled by a dedicated regex pass with dict-callback, not as mega-regex literals. Each token is still individually tracked in the mapping table for reversibility.

**Gap 6 — Short namespaces (< 4 chars).** Very short namespace names were missed because the word-boundary replacement threshold was set at 4 characters. Short namespaces are now replaced contextually in known patterns: `namespace="xxx"`, `"namespace"=>"xxx"`, `/namespaces/xxx/`, and `appName=xxx`. This avoids false positives from substring matches in unrelated text. The OCP cluster name is also auto-extracted from the base domain (e.g. `apps.my-cluster.example.com` → `my-cluster` added as cluster_name).

## License

Community tool, use it at your own risk.
