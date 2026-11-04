import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parents[1]


class UbuntuScriptsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="lore-auth-scripts-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.build = self.root / "build with spaces"
        self.build.mkdir()
        self.bin = self.root / "installed binaries"
        self.record = self.root / "authctl-args"
        self.env = os.environ.copy()
        self.env["TEST_RECORD"] = str(self.record)
        self.executable(self.build / "lore-auth-server", "#!/bin/sh\nexit 0\n")
        self.executable(
            self.build / "lore-authctl",
            '#!/bin/sh\nprintf "%s\\n" "$@" > "$TEST_RECORD"\n',
        )

    def executable(self, path, text):
        path.write_text(text, encoding="utf-8")
        path.chmod(0o755)

    def run_script(self, name, *args, env=None, ok=True):
        result = subprocess.run(
            ["bash", str(SCRIPTS / name), *map(str, args)],
            text=True,
            capture_output=True,
            env=env or self.env,
            check=False,
        )
        if ok:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout)
        return result

    def install(self, *args, ok=True):
        return self.run_script(
            "install-bridge-ubuntu.sh",
            "--build-dir",
            self.build,
            "--bin-dir",
            self.bin,
            *args,
            ok=ok,
        )

    def test_build_uses_locked_bridge_packages_and_custom_target(self):
        mock_bin = self.root / "mock-bin"
        mock_bin.mkdir()
        self.executable(mock_bin / "cargo", '#!/bin/sh\nprintf "%s\\n" "$@" > "$TEST_RECORD"\n')
        env = self.env.copy()
        env["PATH"] = str(mock_bin) + os.pathsep + env["PATH"]
        target = self.root / "cargo target"
        self.run_script("build-ubuntu.sh", "--target-dir", target, env=env)
        self.assertEqual(
            self.record.read_text(encoding="utf-8").splitlines(),
            [
                "build",
                "--locked",
                "--release",
                "--target-dir",
                str(target),
                "-p",
                "lore-auth-server",
                "-p",
                "lore-authctl",
            ],
        )

    def test_install_without_initialization_only_installs_binaries(self):
        self.install()
        self.assertEqual(
            {path.name for path in self.bin.iterdir()},
            {"lore-auth-server", "lore-authctl"},
        )
        self.assertFalse(self.record.exists())
        self.assertEqual(stat.S_IMODE((self.bin / "lore-auth-server").stat().st_mode), 0o755)

    def test_database_initialization_uses_explicit_config(self):
        config = self.root / "bridge config.yaml"
        config.write_text("database:\n  path: test.sqlite3\n", encoding="utf-8")
        self.install("--init-db", "--config", config)
        self.assertEqual(
            self.record.read_text(encoding="utf-8").splitlines(),
            ["--config", str(config), "init-db"],
        )

    def test_invalid_options_fail_before_installation(self):
        self.install("--init-db", ok=False)
        self.assertFalse(self.bin.exists())
        self.install("--cert-host", "localhost", ok=False)
        self.assertFalse(self.bin.exists())
        (self.build / "lore-authctl").unlink()
        self.install(ok=False)
        self.assertFalse(self.bin.exists())

    @unittest.skipUnless(shutil.which("openssl"), "openssl is required")
    def test_certificate_san_permissions_and_no_overwrite(self):
        cert_dir = self.root / "certificates"
        self.install("--init-cert", cert_dir, "--cert-host", "192.0.2.1")
        key = cert_dir / "grpc.key"
        cert = cert_dir / "grpc.crt"
        self.assertEqual(stat.S_IMODE(key.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(cert.stat().st_mode), 0o644)
        certificate = subprocess.run(
            ["openssl", "x509", "-in", str(cert), "-noout", "-text"],
            text=True,
            capture_output=True,
            check=True,
        ).stdout
        self.assertIn("IP Address:192.0.2.1", certificate)
        self.assertIn("CA:FALSE", certificate)
        self.assertIn("TLS Web Server Authentication", certificate)
        original = cert.read_bytes()
        self.install("--init-cert", cert_dir, "--cert-host", "localhost", ok=False)
        self.assertEqual(cert.read_bytes(), original)

    @unittest.skipUnless(shutil.which("openssl"), "openssl is required")
    def test_dns_certificate_and_combined_initialization(self):
        config = self.root / "bridge.yaml"
        config.write_text("database:\n  path: test.sqlite3\n", encoding="utf-8")
        cert_dir = self.root / "cert"
        self.install(
            "--init-db",
            "--config",
            config,
            "--init-cert",
            cert_dir,
            "--cert-host",
            "auth.example.test",
        )
        cert = subprocess.run(
            ["openssl", "x509", "-in", str(cert_dir / "grpc.crt"), "-noout", "-ext", "subjectAltName"],
            text=True,
            capture_output=True,
            check=True,
        ).stdout
        self.assertIn("DNS:auth.example.test", cert)
        self.assertTrue(self.record.exists())


if __name__ == "__main__":
    unittest.main()
