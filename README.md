# K10 Log Bundle Anonymizer

A Python utility that anonymizes sensitive infrastructure data from **Kasten K10** support log bundles, making them safe to share externally (e.g. with Veeam Support) while preserving log structure and debuggability.

## Why

K10's built-in log collector (`k10tools`) does a good job masking secret values, but the resulting bundle still contains infrastructure fingerprinting data: cluster identity, internal IPs, storage targets, FQDNs, and customer workload namespaces. This script replaces those with consistent, deterministic fake values and produces a **reversible mapping table** so the original data can be recovered internally if needed.

## What gets anonymized

| # | Category | Example (before → after) |
|---|----------|--------------------------|
| 1 | **Cluster identity** – UUIDs and short names | `a1b2c3d4-e5f6-…` → `00000000-…-ef0000000001`, `my-ocp-cluster` → `cluster01` |
| 2 | **FQDNs / OpenShift routes** – any TLD | `kasten.apps.my-ocp-cluster.example.com` → `redacted-host02.example.internal` |
| 3 | **Object storage** – endpoints, buckets, S3 access keys | `s3.region.provider.net` → `s3.anon-storage01.example.com` |
| 4 | **IP addresses** – pod IPs, ClusterIPs, node IPs | `10.131.2.45` → `198.51.0.21` |
| 5 | **Customer workload namespaces** – all lengths | `my-app-staging` → `app-ns-005`, `dev` → `app-ns-001` |
| 6 | **Kopia debug logs** – S3 URLs, AWS SigV4 Credential= | `Credential=ABCD1234…/date/region/s3/…` → `Credential=REDACTED_ACCESS_KEY_002/…` |
| 7 | **OIDC auth tokens** – authorization codes and state params | `code=xyzabc123…` → `code=REDACTED_OIDC_CODE_0013` |

Standard OpenShift (`openshift-*`) and K10 (`kasten-io`) namespaces are **preserved** so logs remain useful for troubleshooting.

## Requirements

- Python 3.10+
- No external dependencies (stdlib only)
- Optional: `pyahocorasick` for faster literal matching on large pattern sets (see [Aho-Corasick acceleration](#optional-aho-corasick-acceleration))

## Quick start

```bash
# 1. Extract the K10 log bundle
unzip k10logs.zip -d k10logs

# 2. Run the anonymizer
python3 k10_log_anonymizer_v3.py k10logs/k10logs anonymized_logs

# 3. Review the output
cat anonymized_logs/_anonymization_summary.txt
```

## Usage

```
python3 k10_log_anonymizer_v3.py <input_dir> <output_dir>
```

| Argument | Description |
|----------|-------------|
| `input_dir` | Path to the extracted K10 log bundle directory |
| `output_dir` | Destination for the anonymized copy (created if missing) |

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

**Detection** accounts for ~63% of total time. Files are read once and cached in memory for reuse during replacement. Detection patterns are split into two groups: "always-scan" patterns (IPs and domains, which have no cheap keyword trigger) and "keyword-gated" patterns (namespace, bucket, endpoint, cluster, accessKeyID) that only run on files containing the relevant keyword.

**Replacement** uses a multi-pass strategy, each pass optimized for its data type:

1. **Non-IP literals** (domains, UUIDs, endpoints, access keys, namespaces ≥ 4 chars, bucket names, cluster names) — single compiled alternation regex or Aho-Corasick trie, with dict callback.
2. **IP addresses** — single `\d+\.\d+\.\d+\.\d+` pattern with dict lookup. Separate from literals because a pattern-based approach is 46% faster than 300+ IP alternations.
3. **OIDC codes and states** — dedicated regex patterns (`code=xxx`, `state=oidc-auth-state-xxx`) with dict callback. Kept separate from the mega-regex to avoid performance degradation when thousands of unique tokens are present.
4. **Short namespaces** (< 4 chars) — contextual regex that only replaces in known patterns (`namespace=`, `appName=`, `/namespaces/`, `"namespace"=>`), avoiding false positives from substring matches.

### Optional: Aho-Corasick acceleration

If `pyahocorasick` is installed (`pip install pyahocorasick`), the script automatically uses it for the non-IP literal matching pass. This replaces the regex alternation with an O(text_length) trie automaton, which scales better when the number of patterns grows into the hundreds (large multi-cluster environments with many namespaces, domains, and endpoints). For bundles with fewer than ~50 non-IP patterns, the built-in mega-regex is already efficient and Aho-Corasick is not required.

### Going further: Rust/PyO3

For extreme throughput requirements (multi-GB bundles, automated pipelines processing dozens of bundles per day), the detection and replacement hot paths can be rewritten in Rust using PyO3. The Rust `aho_corasick` and `regex` crates (the same ones behind `ripgrep`) provide SIMD-accelerated matching that can reach 50–100 MB/s. The Python script would import the compiled Rust module as a drop-in replacement, with automatic fallback to pure Python if the Rust extension is not installed.

## Design decisions

**Consistency** — The same original value always produces the same anonymized value across all log files. If an IP appears in both `gateway` and `executor-svc` logs, it maps to the same anonymized IP in both.

**Single-read architecture** — Every file is read once during detection, cached in memory, then reused for replacement. This eliminates the double I/O cost of scanning then re-reading.

**IP range choice** — Anonymized IPs use `198.51.0.0/24` (RFC 5737 TEST-NET-2), a range explicitly reserved for documentation and examples that will never collide with real infrastructure.

**Multi-format support** — K10 logs mix several formats and the replacer handles all of them: standard JSON (`"cluster_name":"a1b2c3d4-…"`), Fluentd/Ruby (`"namespace"=>"my-app"`), Prometheus labels (`bucket="my-bucket"`), freetext (Kopia `description` strings, URL query params like `cl=my-cluster` or `appName=dev`), Kopia HTTP debug dumps (full S3 request URLs with `Authorization: AWS4-HMAC-SHA256 Credential=…`), and OIDC redirect URLs (`code=xxx&state=oidc-auth-state-xxx`).

**Safe-list approach** — Platform namespaces (`openshift-*`, `kube-*`, `kasten-io`) and K8s/OCP API groups are explicitly preserved. Only customer-specific namespaces get anonymized.

**No K8s secrets in scope** — The script does not target K8s Secret values (they're already masked by K10's collector as `<set to the key ... in secret ...>`). It does catch: S3 access key IDs from both `accessKeyID=` fields and AWS SigV4 `Credential=` headers in Kopia HTTP debug logs, and OIDC authorization codes and state tokens from gateway redirect URLs.

## Customization

The script has configuration constants at the top of the file that can be adjusted per environment:

| Constant | Purpose |
|----------|---------|
| `KNOWN_SAFE_NAMESPACES` | Namespaces that should never be anonymized |
| `SAFE_NAMESPACE_PREFIXES` | Namespace prefixes to preserve (e.g. `openshift-`) |
| `IP_PASSTHROUGH` | IPs to skip (loopback, unspecified) |
| `SAFE_DOMAIN_PATTERNS` | FQDNs that are API groups, not infrastructure |
| `SAFE_DOMAIN_SUBSTRINGS` | Domain substrings to always preserve |

### Adding new detection patterns

To anonymize additional categories:

1. Add a new `set()` in `detect_and_cache()` with the appropriate regex — if the pattern has a keyword anchor (e.g. `vaultAddr`), add it to the gated patterns list for efficiency.
2. In `build_replacer()`, decide the replacement strategy:
   - **Literal** (few unique values, e.g. hostnames): add to `non_ip_lookup` → goes into the mega-regex.
   - **Pattern-based** (many unique values, e.g. session IDs): add a dedicated regex pass in `replace_content()` with dict callback.
   - **Contextual** (short values, false-positive risk): add to a separate contextual replacement like `short_ns_patterns`.

## Limitations

- **Pod and container names** are not anonymized (they contain K10 component names, not customer data).
- **Timestamps** are preserved as-is (needed for log correlation).
- **K8s resource UUIDs** (action IDs, manifest IDs) are not anonymized — only the cluster UUID is. This is intentional: action UUIDs are needed for troubleshooting and are not externally meaningful.
- **Secret checksums** (e.g. `checksum/secret: abc123…`) are left in place. They are SHA hashes of the secret content, not the secret itself, and are useful for verifying that all pods share the same secret version.
- The script processes text files only. Binary content (if any) is skipped.

## Changelog

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
