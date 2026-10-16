"""Public templates contain no credential; local TLS injection preserves YAML fields."""
import importlib.util
import os
import tempfile
import unittest


def load_tool(name):
    path = os.path.join(os.path.dirname(__file__), "..", name + ".py")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PublicTLS(unittest.TestCase):
    def test_local_injection_and_replacement(self):
        tool = load_tool("configure-agh-tls")
        with tempfile.TemporaryDirectory() as work:
            paths = [os.path.join(work, name) for name in ("cert", "key", "agh")]
            cert, key, config = paths
            for path, text in zip(paths, (
                    "TEST CERTIFICATE\nSECOND LINE\n", "TEST PRIVATE MATERIAL\n",
                    'tls:\n  certificate_chain: ""\n  private_key: ""\n'
                    '  strict_sni_check: false\nnext: true\n')):
                with open(path, "w") as stream:
                    stream.write(text)
            tool.configure(cert, key, [config])
            tool.configure(cert, key, [config])
            with open(config) as stream:
                result = stream.read()
            self.assertEqual(result.count("TEST CERTIFICATE"), 1)
            self.assertIn("    SECOND LINE\n", result)
            self.assertIn("  strict_sni_check: false\nnext: true\n", result)

    def test_missing_fields_reject_without_writing(self):
        tool = load_tool("configure-agh-tls")
        with tempfile.TemporaryDirectory() as work:
            cert, key, config = [os.path.join(work, x) for x in ("cert", "key", "agh")]
            for path in (cert, key):
                with open(path, "w") as stream:
                    stream.write("TEST MATERIAL")
            with open(config, "w") as stream:
                stream.write('tls:\n  certificate_chain: ""\n')
            with self.assertRaises(ValueError):
                tool.configure(cert, key, [config])
            with open(config) as stream:
                self.assertNotIn("TEST MATERIAL", stream.read())

    def test_scanner_rejects_key_and_accepts_repository_url(self):
        scanner = load_tool("check-public-data")
        marker = b"-----BEGIN " + b"RSA PRIVATE KEY-----"
        self.assertIn("private key", scanner.violations(marker))
        self.assertEqual(scanner.violations(
            b"https://github.com/Logic769/dns-guard-stack"), [])
