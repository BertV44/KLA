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
| 5 | **IP addresses** – pod IPs, ClusterIPs, node IPs | `10.128.1.223` → `198.51.0.21` |
| 7 | **Customer workload namespaces** | `pacman` → `app-ns-002` |

Standard OpenShift (`openshift-*`) and K10 (`kasten-io`) namespaces are **preserved** so logs remain useful for troubleshooting.

## Performance

Three versions are provided, each building on profiling data from the previous:

| Version | Approach | Speed | Best for |
|---------|----------|-------|----------|
| `k10_log_anonymizer.py` (v1) | Per-line loop over each detected value | ~3.7 MB/s | Readability, easy to extend |
| `k10_log_anonymizer_v2.py` (v2) | Single-pass compiled mega-regex | ~9.7 MB/s | Good balance of speed and simplicity |
| `k10_log_anonymizer_v3.py` (v3) | Single-read cache + split mega-regex/IP pattern | ~11.8 MB/s | Large bundles, production use |

Benchmarked on a 95 MB / 306k-line bundle (22 files, 65 unique patterns):

| | v1 | v2 | v3 |
|---|---|---|---|
| Total time | 26.1s | 9.9s | 8.1s |
| Throughput | 3.7 MB/s | 9.7 MB/s | 11.8 MB/s |

**Projected for larger bundles:**

| Bundle size | v1 | v2 | v3 |
|-------------|-----|-----|-----|
| 200 MB | ~54s | ~21s | ~17s |
| 500 MB | ~2m15s | ~52s | ~42s |
| 1 GB | ~4m30s | ~1m43s | ~1m25s |

### Where the time goes (v3 profiling)

Detection (reading + regex scanning) accounts for ~63% of total time. The two most expensive detection patterns are domain matching (scanning for `.apps.`, `.home`, `.local` etc.) and IP extraction, which together represent ~75% of the detection phase. These are fundamentally expensive because they must examine every character position in the text.

Replacement accounts for ~37%. The key optimization between v2 and v3 is **not** putting IP addresses into the mega-regex. Profiling showed that a single `\d+\.\d+\.\d+\.\d+` pattern with a dict callback is **46% faster** than 51 literal IP alternations, because the regex engine handles character-class patterns far more efficiently than long alternation lists.

Multiprocessing was tested and proved **counterproductive** on bundles under 200 MB — the cost of serializing file content to worker processes (pickle overhead) exceeds the parallelism gains.

### Optional: Aho-Corasick acceleration

If `pyahocorasick` is installed (`pip install pyahocorasick`), v3 will automatically use it for the non-IP literal matching pass. This replaces the regex alternation with an O(text_length) trie automaton, which scales better when the number of patterns grows into the hundreds (large multi-cluster environments with many namespaces, domains, and endpoints).

## Requirements

- Python 3.10+
- No external dependencies (stdlib only)

## Quick start

```bash
# 1. Extract the K10 log bundle
unzip k10logs.zip -d k10logs

# 2. Run the anonymizer (pick your version)
python3 k10_log_anonymizer.py k10logs/k10logs anonymized_logs       # v1 – simple, readable
python3 k10_log_anonymizer_v2.py k10logs/k10logs anonymized_logs    # v2 – compiled mega-regex
python3 k10_log_anonymizer_v3.py k10logs/k10logs anonymized_logs    # v3 – fastest, recommended

# 3. Review the output
cat anonymized_logs/_anonymization_summary.txt
```

## Usage

```
python3 k10_log_anonymizer.py <input_dir> <output_dir>       # v1
python3 k10_log_anonymizer_v2.py <input_dir> <output_dir>    # v2
python3 k10_log_anonymizer_v3.py <input_dir> <output_dir>    # v3 (recommended)
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

## Design decisions

**Consistency** — The same original value always produces the same anonymized value across all 22+ log files. If `10.128.1.223` appears in both `gateway` and `executor-svc` logs, it maps to `198.51.0.21` in both.

**IP range choice** — Anonymized IPs use `198.51.100.0/24` (RFC 5737 TEST-NET-2), a range explicitly reserved for documentation and examples that will never collide with real infrastructure.

**Multi-format support** — K10 logs mix several formats. The replacer handles all of them:
- Standard JSON: `"cluster_name":"9969be77-..."`
- Fluentd/Ruby: `"namespace"=>"pacman"`
- Prometheus labels: `bucket="oc02", endpoint="https://gateway.storjshare.io"`
- Freetext: Kopia `description` strings, URL query params (`cl=oc02`)

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

To anonymize additional categories, add:

1. A new `set()` in `detect_values()` with the appropriate regex
2. A new `anon_*()` helper function with a format template
3. The replacement logic in `build_replacer()` → `replace_line()`

## Limitations

- **Pod and container names** are not anonymized (they contain K10 component names, not customer data).
- **Timestamps** are preserved as-is (needed for log correlation).
- **K8s resource UUIDs** (action IDs, manifest IDs) are not anonymized — only the cluster UUID is. This is intentional: action UUIDs are needed for troubleshooting and are not externally meaningful.
- **Secret checksums** (e.g. `checksum/secret: e21618e...`) are left in place. They are SHA hashes of the secret content, not the secret itself, and are useful for verifying that all pods share the same secret version.
- The script processes text files only. Binary content (if any) is skipped.

## License

Internal tooling — adapt and redistribute as needed within your TAM practice.
