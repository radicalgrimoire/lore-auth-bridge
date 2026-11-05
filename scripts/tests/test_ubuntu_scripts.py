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

    def nginx_setup(self, *args, ok=True, nginx_status=0):
        nginx_dir = self.root / "nginx"
        mock_bin = self.root / "nginx-bin"
        if not nginx_dir.exists():
            (nginx_dir / "sites-available").mkdir(parents=True)
            (nginx_dir / "sites-enabled").mkdir()
            (nginx_dir / "nginx.conf").write_text("", encoding="utf-8")
            (self.root / "cert.pem").write_text("certificate", encoding="utf-8")
            (self.root / "key.pem").write_text("key", encoding="utf-8")
            mock_bin.mkdir()
        self.executable(
            mock_bin / "nginx",
            f'#!/bin/sh\nprintf "%s\\n" "$@" > "$TEST_RECORD"\nexit {nginx_status}\n',
        )
        env = self.env.copy()
        env["PATH"] = str(mock_bin) + os.pathsep + env["PATH"]
        return self.run_script(
            "configure-nginx-ubuntu.sh",
            "--nginx-dir", nginx_dir,
            "--server-host", "auth.example.test",
            "--cert", self.root / "cert.pem",
            "--key", self.root / "key.pem",
            *args,
            env=env,
            ok=ok,
        )

    def test_nginx_site_and_restricted_endpoints(self):
        self.nginx_setup(
            "--rebac-allow", "192.0.2.10",
            "--admin-allow", "198.51.100.0/24",
        )
        nginx = self.root / "nginx"
        site = nginx / "sites-available" / "lore-auth"
        enabled = nginx / "sites-enabled" / "lore-auth"
        config = site.read_text(encoding="utf-8")
        self.assertEqual(enabled.resolve(), site)
        self.assertEqual(stat.S_IMODE(site.stat().st_mode), 0o644)
        self.assertIn("proxy_pass http://127.0.0.1:18080;", config)
        self.assertIn("grpc_pass grpcs://127.0.0.1:18081;", config)
        self.assertIn("grpc_set_header x-lore-client-ip $remote_addr;", config)
        self.assertEqual(config.count("proxy_set_header x-lore-client-ip $remote_addr;"), 2)
        self.assertIn("allow 198.51.100.0/24;\n        deny all;", config)
        self.assertIn("allow 192.0.2.10;\n        deny all;", config)
        self.assertEqual(config.count("access_log off;"), 2)
        self.assertEqual(
            self.record.read_text(encoding="utf-8").splitlines(),
            ["-t", "-p", str(nginx) + "/", "-c", str(nginx / "nginx.conf")],
        )

    def test_nginx_default_restrictions_and_no_overwrite(self):
        self.nginx_setup()
        site = self.root / "nginx" / "sites-available" / "lore-auth"
        original = site.read_bytes()
        self.assertEqual(original.count(b"allow 127.0.0.1;"), 2)
        self.assertEqual(original.count(b"deny all;"), 2)
        self.nginx_setup(ok=False)
        self.assertEqual(site.read_bytes(), original)
        self.assertTrue((self.root / "nginx" / "sites-enabled" / "lore-auth").is_symlink())

    def test_nginx_failed_test_rolls_back_created_site(self):
        self.nginx_setup(ok=False, nginx_status=1)
        nginx = self.root / "nginx"
        self.assertEqual(list((nginx / "sites-available").iterdir()), [])
        self.assertEqual(list((nginx / "sites-enabled").iterdir()), [])

    def test_nginx_rejects_invalid_addresses_and_config_injection(self):
        for option, value in [
            ("--rebac-allow", "192.0.2.256"),
            ("--admin-allow", "192.0.2.0/33"),
            ("--admin-allow", "192.0.2.1;allow all"),
            ("--server-host", "example.test;include"),
        ]:
            with self.subTest(value=value):
                self.nginx_setup(option, value, ok=False)
                self.assertEqual(list((self.root / "nginx" / "sites-available").iterdir()), [])
                self.assertFalse(self.record.exists())

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
