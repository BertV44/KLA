#!/usr/bin/env python3
"""
Basic unit tests for k10_log_anonymizer.

Run with:
  python3 -m unittest test_anonymizer.py -v
"""

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

# Import the module under test
import sys
sys.path.insert(0, os.path.dirname(__file__))
import k10_log_anonymizer as anon


class TestIsTextFile(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def _write(self, name, content_bytes):
        path = os.path.join(self.tmp, name)
        with open(path, "wb") as f:
            f.write(content_bytes)
        return path

    def test_plain_text(self):
        p = self._write("a.log", b"hello world\nfoo bar\n")
        self.assertTrue(anon.is_text_file(p))

    def test_empty_file(self):
        p = self._write("empty.log", b"")
        self.assertTrue(anon.is_text_file(p))

    def test_nul_byte_means_binary(self):
        p = self._write("bin.dat", b"data\x00more")
        self.assertFalse(anon.is_text_file(p))

    def test_invalid_utf8_means_binary(self):
        # 0xC3 alone is an invalid UTF-8 sequence
        p = self._write("bad.dat", b"prefix\xc3\xc3\xc3suffix")
        self.assertFalse(anon.is_text_file(p))

    def test_utf8_with_accents_is_text(self):
        p = self._write("fr.log", "événement déclenché".encode("utf-8"))
        self.assertTrue(anon.is_text_file(p))


class TestMappingStore(unittest.TestCase):
    def test_get_or_create_is_stable(self):
        s = anon.MappingStore()
        r1 = s.get_or_create("cat", "value", lambda n: f"anon{n}")
        r2 = s.get_or_create("cat", "value", lambda n: f"anon{n}")
        self.assertEqual(r1, r2)
        self.assertEqual(r1, "anon1")

    def test_counter_increments(self):
        s = anon.MappingStore()
        a = s.get_or_create("cat", "v1", lambda n: f"x{n}")
        b = s.get_or_create("cat", "v2", lambda n: f"x{n}")
        self.assertEqual(a, "x1")
        self.assertEqual(b, "x2")

    def test_load_existing_resumes_counter(self):
        s = anon.MappingStore()
        s.load_existing({"cat": {"old1": "x1", "old2": "x2"}})
        c = s.get_or_create("cat", "new", lambda n: f"x{n}")
        self.assertEqual(c, "x3")  # counter resumed at 3

    def test_load_existing_preserves_old(self):
        s = anon.MappingStore()
        s.load_existing({"cat": {"old1": "x1"}})
        r = s.get_or_create("cat", "old1", lambda n: f"x{n}")
        self.assertEqual(r, "x1")


class TestIPPattern(unittest.TestCase):
    def test_valid_ip(self):
        self.assertIsNotNone(anon.PAT_IP.search("ip 10.131.2.45 end"))

    def test_octet_above_255_rejected(self):
        # 999 is invalid; PAT_IP must not match it
        m = anon.PAT_IP.search("ip 10.999.2.45 end")
        self.assertIsNone(m)

    def test_version_string_partial_match(self):
        # 1.2.3.4 is a syntactically valid IP, will match — expected.
        # The test documents this known limitation.
        self.assertIsNotNone(anon.PAT_IP.search("version 1.2.3.4 deployed"))


class TestPipeline(unittest.TestCase):
    """End-to-end test on a realistic mini-bundle."""

    def setUp(self):
        self.indir = tempfile.mkdtemp()
        self.outdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.indir, ignore_errors=True)
        shutil.rmtree(self.outdir, ignore_errors=True)

    def _write(self, name, content):
        path = os.path.join(self.indir, name)
        if isinstance(content, str):
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
        else:
            with open(path, "wb") as f:
                f.write(content)

    def test_basic_anonymization(self):
        self._write("gateway.log",
            "cluster_name=a1b2c3d4-e5f6-7890-abcd-ef1234567890\n"
            "route: kasten.apps.my-cluster.example.com\n"
            "pod-ip 10.131.2.45\n")
        self._write("catalog.log",
            '{"namespace":"my-app-prod"}\n'
            '{"namespace":"dev"}\n'
            'accessKeyID=AKIAIOSFODNN7EXAMPLE\n')

        anon.process_bundle(self.indir, self.outdir)

        # Verify mapping file exists
        mapping_path = os.path.join(self.outdir, "_anonymization_mapping.json")
        self.assertTrue(os.path.isfile(mapping_path))
        with open(mapping_path) as f:
            mapping = json.load(f)

        # UUID was anonymized
        self.assertIn("a1b2c3d4-e5f6-7890-abcd-ef1234567890", mapping["cluster_uuid"])

        # Domain was anonymized
        self.assertIn("kasten.apps.my-cluster.example.com", mapping["domain"])

        # Verify content was replaced
        with open(os.path.join(self.outdir, "gateway.log")) as f:
            gateway = f.read()
        self.assertNotIn("a1b2c3d4-e5f6", gateway)
        self.assertNotIn("kasten.apps.my-cluster.example.com", gateway)
        self.assertNotIn("10.131.2.45", gateway)

        with open(os.path.join(self.outdir, "catalog.log")) as f:
            catalog = f.read()
        self.assertNotIn("my-app-prod", catalog)
        # Short namespace 'dev' replaced via contextual pattern
        self.assertNotIn('"namespace":"dev"', catalog)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", catalog)

    def test_binary_file_copied_verbatim(self):
        self._write("text.log", "namespace=my-app\n")
        binary_content = b"\x00\x01\x02\xff\xfeSOME_BINARY\x00data"
        self._write("data.bin", binary_content)

        anon.process_bundle(self.indir, self.outdir)

        with open(os.path.join(self.outdir, "data.bin"), "rb") as f:
            out_bytes = f.read()
        self.assertEqual(out_bytes, binary_content,
                         "Binary file must be copied byte-for-byte")

    def test_longest_match_wins_in_overlap(self):
        """A cluster short name embedded in a longer FQDN must not be replaced
        independently — the FQDN match takes precedence."""
        self._write("test.log",
            "domain: kasten.apps.my-cluster.example.com\n"
            "cluster=my-cluster\n")

        anon.process_bundle(self.indir, self.outdir)

        with open(os.path.join(self.outdir, "test.log")) as f:
            out = f.read()

        # The full domain should appear as a single redacted-host
        self.assertIn("redacted-host", out)
        # The cluster short name should also be replaced (standalone occurrence)
        self.assertIn("cluster01", out)
        # Critically: the result must NOT contain a partial substitution like
        # "kasten.apps.cluster01.example.com" — the domain match wins
        self.assertNotIn("kasten.apps.cluster01.example.com", out)

    def test_oidc_code_and_state_replaced(self):
        self._write("gateway.log",
            "redirect: /callback?code=xyzabc123def456ghijkl"
            "&state=oidc-auth-state-abcdef1234567890\n")

        anon.process_bundle(self.indir, self.outdir)

        with open(os.path.join(self.outdir, "gateway.log")) as f:
            out = f.read()
        self.assertNotIn("xyzabc123def456ghijkl", out)
        self.assertNotIn("oidc-auth-state-abcdef1234567890", out)
        self.assertIn("REDACTED_OIDC_CODE_", out)
        self.assertIn("oidc-auth-state-redacted-", out)

    def test_aws_sigv4_credential(self):
        self._write("kopia.log",
            "Authorization: AWS4-HMAC-SHA256 "
            "Credential=AKIAIOSFODNN7EXAMPLE/20260515/us-east-1/s3/aws4_request\n")

        anon.process_bundle(self.indir, self.outdir)

        with open(os.path.join(self.outdir, "kopia.log")) as f:
            out = f.read()
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", out)
        self.assertIn("REDACTED_ACCESS_KEY_", out)

    def test_s3_url_with_region(self):
        """S3 URLs containing dashes in the region (e.g. us-east-1) must be detected."""
        self._write("kopia_debug.log",
            "GET https://s3.us-east-1.amazonaws.com/customer-bucket/key HTTP/1.1\n")

        anon.process_bundle(self.indir, self.outdir)

        with open(os.path.join(self.outdir, "kopia_debug.log")) as f:
            out = f.read()
        self.assertNotIn("s3.us-east-1.amazonaws.com", out)
        self.assertNotIn("customer-bucket", out)

    def test_safe_namespaces_preserved(self):
        self._write("test.log",
            'namespace="openshift-monitoring"\n'
            'namespace="kasten-io"\n'
            'namespace="kube-system"\n'
            'namespace="customer-app"\n')

        anon.process_bundle(self.indir, self.outdir)

        with open(os.path.join(self.outdir, "test.log")) as f:
            out = f.read()
        # Platform namespaces preserved
        self.assertIn("openshift-monitoring", out)
        self.assertIn("kasten-io", out)
        self.assertIn("kube-system", out)
        # Customer namespace anonymized
        self.assertNotIn("customer-app", out)

    def test_incremental_mapping_consistency(self):
        """Same input value across two runs (with --mapping-in) must yield
        the same anonymized output."""
        self._write("a.log", "cluster=my-cluster\nip 10.0.0.5\n")
        outdir1 = tempfile.mkdtemp()
        try:
            anon.process_bundle(self.indir, outdir1)
            mapping1 = os.path.join(outdir1, "_anonymization_mapping.json")

            # Second bundle in fresh directory
            indir2 = tempfile.mkdtemp()
            outdir2 = tempfile.mkdtemp()
            try:
                with open(os.path.join(indir2, "b.log"), "w") as f:
                    f.write("cluster=my-cluster\nip 10.0.0.5\nip 10.0.0.99\n")

                anon.process_bundle(indir2, outdir2, mapping_in=mapping1)

                with open(os.path.join(outdir2, "b.log")) as f:
                    out2 = f.read()
                with open(os.path.join(outdir1, "a.log")) as f:
                    out1 = f.read()

                # Same values produce same anonymized outputs
                # Extract the cluster replacement from out1
                import re
                m1 = re.search(r"cluster=(\w+)", out1)
                m2 = re.search(r"cluster=(\w+)", out2)
                self.assertEqual(m1.group(1), m2.group(1))
            finally:
                shutil.rmtree(indir2, ignore_errors=True)
                shutil.rmtree(outdir2, ignore_errors=True)
        finally:
            shutil.rmtree(outdir1, ignore_errors=True)


class TestRegressionsV33(unittest.TestCase):
    """Regression tests for the four bugs fixed in v3.3."""

    def setUp(self):
        self.indir = tempfile.mkdtemp()
        self.outdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.indir, ignore_errors=True)
        shutil.rmtree(self.outdir, ignore_errors=True)

    def _write(self, name, content):
        path = os.path.join(self.indir, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)

    def test_short_cluster_name_word_boundary(self):
        """v3.3 bug 1: a short cluster_name like 'prod' must NOT match inside
        'production', 'reproduce', 'prod-service'. Only contextual anchors
        (cluster=, cluster_name=, /clusters/) trigger replacement."""
        self._write("a.log",
            "cluster=prod\n"
            "service production deployed\n"
            "command reproduce please\n"
            "another-prod-service-name\n")

        anon.process_bundle(self.indir, self.outdir)

        with open(os.path.join(self.outdir, "a.log")) as f:
            out = f.read()
        # The anchored occurrence must be replaced
        self.assertIn("cluster=cluster", out)
        self.assertNotIn("cluster=prod\n", out)
        # The unanchored occurrences must stay intact
        self.assertIn("production", out)
        self.assertIn("reproduce", out)
        self.assertIn("another-prod-service-name", out)
        # And critically: no corruption like "cluster01uction"
        self.assertNotIn("uction", out.replace("production", ""))

    def test_namespace_only_in_url_path(self):
        """v3.3 bug 3: a namespace appearing ONLY in /api/v1/namespaces/<ns>/
        must be detected and anonymized (audit logs, raw API traces)."""
        self._write("audit.log",
            "GET /api/v1/namespaces/customer-app/pods\n"
            "POST /api/v1/namespaces/another-ns/configmaps\n")

        anon.process_bundle(self.indir, self.outdir)

        with open(os.path.join(self.outdir, "audit.log")) as f:
            out = f.read()
        self.assertNotIn("customer-app", out)
        self.assertNotIn("another-ns", out)
        self.assertIn("/namespaces/app-ns-", out)

    def test_mixed_case_uuid_replaced(self):
        """v3.3 bug 4: UUIDs in mixed case must be detected and anonymized
        consistently with their lowercase form (case-insensitive lookup)."""
        self._write("a.log",
            "cluster_name=A1b2C3d4-E5f6-7890-AbCd-Ef1234567890\n"
            "cluster_name=a1b2c3d4-e5f6-7890-abcd-ef1234567890\n"
            "cluster_name=A1B2C3D4-E5F6-7890-ABCD-EF1234567890\n")

        anon.process_bundle(self.indir, self.outdir)

        with open(os.path.join(self.outdir, "a.log")) as f:
            out = f.read()
        # None of the three casings must survive
        self.assertNotIn("a1b2c3d4-e5f6", out.lower())
        # All three lines must resolve to the same anonymized UUID
        lines = [l for l in out.strip().split("\n") if l]
        self.assertEqual(len(set(lines)), 1,
                         f"All casings should map to the same value, got: {lines}")

    def test_double_pass_is_stable(self):
        """v3.3 bug 2: running the anonymizer on its own output must be a
        no-op (idempotent). Previously the regenerated output suffix
        '.example.internal' was re-matched as an internal TLD."""
        self._write("a.log",
            "cluster_name=a1b2c3d4-e5f6-7890-abcd-ef1234567890\n"
            "host kasten.apps.my-cluster.example.com\n"
            "ip 10.0.0.5\n")

        anon.process_bundle(self.indir, self.outdir)
        # Read pass 1 result
        with open(os.path.join(self.outdir, "a.log")) as f:
            pass1 = f.read()

        # Strip mapping files so we can re-run on the output
        os.remove(os.path.join(self.outdir, "_anonymization_mapping.json"))
        os.remove(os.path.join(self.outdir, "_anonymization_summary.txt"))

        outdir2 = tempfile.mkdtemp()
        try:
            anon.process_bundle(self.outdir, outdir2)
            with open(os.path.join(outdir2, "a.log")) as f:
                pass2 = f.read()
            self.assertEqual(pass1, pass2,
                             "Second pass must be a no-op on anonymized content")

            # And the second-pass mapping must contain nothing genuinely new
            with open(os.path.join(outdir2, "_anonymization_mapping.json")) as f:
                mapping2 = json.load(f)
            total_new = sum(len(v) for v in mapping2.values())
            self.assertEqual(total_new, 0,
                             f"Second pass should detect nothing, got: {mapping2}")
        finally:
            shutil.rmtree(outdir2, ignore_errors=True)


class TestVerifyOutput(unittest.TestCase):
    def setUp(self):
        self.outdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.outdir, ignore_errors=True)

    def test_clean_output(self):
        with open(os.path.join(self.outdir, "clean.log"), "w") as f:
            f.write("ip 198.51.0.42\nhost redacted-host01.example.internal\n")
        findings = anon.verify_output(self.outdir)
        self.assertEqual(findings, {})

    def test_detects_leaked_ip(self):
        with open(os.path.join(self.outdir, "leak.log"), "w") as f:
            f.write("real ip 10.131.2.45 leaked\n")
        findings = anon.verify_output(self.outdir)
        self.assertIn("ip_remaining", findings)

    def test_ignores_anonymized_ips(self):
        with open(os.path.join(self.outdir, "ok.log"), "w") as f:
            f.write("anon 198.51.0.7 ok\n")
        findings = anon.verify_output(self.outdir)
        self.assertNotIn("ip_remaining", findings)


if __name__ == "__main__":
    unittest.main()
