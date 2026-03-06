# K10 Log Bundle Anonymizer

A Python utility that anonymizes sensitive infrastructure data from **Kasten K10** support log bundles, making them safe to share externally (e.g. with Veeam Support) while preserving log structure and debuggability.

## Why

K10's built-in log collector (`k10tools`) does a good job masking secret values, but the resulting bundle still contains infrastructure fingerprinting data: cluster identity, internal IPs, storage targets, FQDNs, and customer workload namespaces. This script replaces those with consistent, deterministic fake values and produces a **reversible mapping table** so the original data can be recovered internally if needed.

## What gets anonymized

| # | Category | Example (before → after) |
|---|----------|--------------------------|
| 1 | **Cluster identity** – UUIDs and short names | `9969be77-a14a-4eb0-bc1b-cf15ce445146` → `00000000-0000-0000-abcd-ef0000000001` |
| 2 | **FQDNs / OpenShift routes** | `k10-route-kasten-io.apps.oc02.home` → `redacted-host08.example.internal` |
| 3 | **Object storage** – endpoints, buckets, S3 access keys | `gateway.storjshare.io` → `s3.anon-storage01.example.com` |
| 4 | **IP addresses** – pod IPs, ClusterIPs, node IPs | `10.128.1.223` → `198.51.0.21` |
| 5 | **Customer workload namespaces** | `pacman` → `app-ns-002` |

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
    "9969be77-a14a-4eb0-bc1b-cf15ce445146": "00000000-0000-0000-abcd-ef0000000001"
  },
  "cluster_name": {
    "oc02": "cluster01"
  },
  "ip_address": {
    "10.128.1.223": "198.51.0.21",
    "172.30.68.164": "198.51.0.4"
  }
}
```

## Performance

Benchmarked on a 95 MB / 306k-line bundle (22 files, 65 unique patterns):

| Metric | Value |
|--------|-------|
| Total time | 8.1s |
| Throughput | 11.8 MB/s |

Projected for larger bundles:

| Bundle size | Estimated time |
|-------------|----------------|
| 200 MB | ~17s |
| 500 MB | ~42s |
| 1 GB | ~1m25s |

### How it works under the hood

The script runs in two phases: **detection** (scan all files to discover sensitive values) and **replacement** (substitute them with anonymized equivalents).

**Detection** accounts for ~63% of total time. Files are read once and cached in memory for reuse during replacement. Detection patterns are split into two groups: "always-scan" patterns (IPs and domains, which have no cheap keyword trigger) and "keyword-gated" patterns (namespace, bucket, endpoint, cluster, accessKeyID) that only run on files containing the relevant keyword.

**Replacement** accounts for ~37%. Non-IP literals (domains, UUIDs, endpoints, access keys, namespaces, cluster names) are compiled into a single alternation regex and replaced in one pass via dict callback. IPs are handled separately through a dedicated `\d+\.\d+\.\d+\.\d+` pattern with dict lookup. This split strategy was measured to be **46% faster** than putting all patterns (including IPs) in one alternation, because the regex engine handles character-class patterns far more efficiently than long literal alternation lists.

### Optional: Aho-Corasick acceleration

If `pyahocorasick` is installed (`pip install pyahocorasick`), the script automatically uses it for the non-IP literal matching pass. This replaces the regex alternation with an O(text_length) trie automaton, which scales better when the number of patterns grows into the hundreds (large multi-cluster environments with many namespaces, domains, and endpoints). For bundles with fewer than ~50 non-IP patterns, the built-in mega-regex is already efficient and Aho-Corasick is not required.

### Going further: Rust/PyO3

For extreme throughput requirements (multi-GB bundles, automated pipelines processing dozens of bundles per day), the detection and replacement hot paths can be rewritten in Rust using PyO3. The Rust `aho_corasick` and `regex` crates (the same ones behind `ripgrep`) provide SIMD-accelerated matching that can reach 50–100 MB/s. The Python script would import the compiled Rust module as a drop-in replacement, with automatic fallback to pure Python if the Rust extension is not installed.

## Design decisions

**Consistency** — The same original value always produces the same anonymized value across all log files. If `10.128.1.223` appears in both `gateway` and `executor-svc` logs, it maps to `198.51.0.21` in both.

**Single-read architecture** — Every file is read once during detection, cached in memory, then reused for replacement. This eliminates the double I/O cost of scanning then re-reading.

**IP range choice** — Anonymized IPs use `198.51.0.0/24` (RFC 5737 TEST-NET-2), a range explicitly reserved for documentation and examples that will never collide with real infrastructure.

**Multi-format support** — K10 logs mix several formats and the replacer handles all of them: standard JSON (`"cluster_name":"9969be77-…"`), Fluentd/Ruby (`"namespace"=>"pacman"`), Prometheus labels (`bucket="oc02"`), and freetext (Kopia `description` strings, URL query params like `cl=oc02`).

**Safe-list approach** — Platform namespaces (`openshift-*`, `kube-*`, `kasten-io`) and K8s/OCP API groups are explicitly preserved. Only customer-specific namespaces get anonymized.

**No secrets in scope** — The script does not target K8s Secret values (they're already masked by K10's collector as `<set to the key ... in secret ...>`). It does catch S3 access key IDs that appear in Kopia repository config dumps inside executor/logging-svc logs.

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
2. Add a `store.get_or_create()` call in `build_replacer()` with the format template and populate either `non_ip_lookup` (for literal replacement) or a dedicated pattern (for regex-based replacement).

## Limitations

- **Pod and container names** are not anonymized (they contain K10 component names, not customer data).
- **Timestamps** are preserved as-is (needed for log correlation).
- **K8s resource UUIDs** (action IDs, manifest IDs) are not anonymized — only the cluster UUID is. This is intentional: action UUIDs are needed for troubleshooting and are not externally meaningful.
- **Secret checksums** (e.g. `checksum/secret: e21618e...`) are left in place. They are SHA hashes of the secret content, not the secret itself, and are useful for verifying that all pods share the same secret version.
- The script processes text files only. Binary content (if any) is skipped.

## License

Internal tooling — adapt and redistribute as needed within your TAM practice.
