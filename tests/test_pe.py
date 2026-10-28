import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from x86arm import cli, pe, shims

FIXTURES = Path(__file__).parent / "fixtures"


def needs(name):
    path = FIXTURES / name
    return unittest.skipUnless(path.exists(), f"{name} not built; run `make fixtures`")


def run_cli(*argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        code = cli.main(list(argv))
    return code, out.getvalue()


class ParseTiny(unittest.TestCase):
    @needs("tiny.exe")
    def setUp(self):
        self.exe = pe.parse(FIXTURES / "tiny.exe")

    def test_headers(self):
        self.assertEqual(self.exe.machine, pe.MACHINE_AMD64)
        self.assertEqual(self.exe.subsystem_name, "console")
        self.assertEqual(self.exe.image_base, 0x140000000)

    def test_entry_point_is_in_executable_text(self):
        section = self.exe.section_for_rva(self.exe.entry_rva)
        self.assertEqual(section.name, ".text")
        self.assertTrue(section.executable)

    def test_imports(self):
        names = {(shims.canonical_dll(i.dll), i.name) for i in self.exe.imports}
        self.assertEqual(names, {
            ("kernel32", "GetStdHandle"),
            ("kernel32", "WriteFile"),
            ("kernel32", "ExitProcess"),
        })

    def test_check_passes(self):
        code, out = run_cli("check", str(FIXTURES / "tiny.exe"))
        self.assertEqual(code, 0, out)


class ParseHello(unittest.TestCase):
    @needs("hello.exe")
    def test_crt_imports_are_reported_missing(self):
        code, out = run_cli("check", str(FIXTURES / "hello.exe"))
        self.assertEqual(code, 1)
        self.assertIn("ucrtbase", out)


class Errors(unittest.TestCase):
    def test_rejects_non_pe(self):
        with tempfile.NamedTemporaryFile(suffix=".exe") as f:
            f.write(b"not an exe" * 10)
            f.flush()
            with self.assertRaises(pe.PEError):
                pe.parse(f.name)
            code, out = run_cli("info", f.name)
            self.assertEqual(code, 2)
            self.assertIn("MZ", out)


class Shims(unittest.TestCase):
    def test_canonical_dll(self):
        self.assertEqual(shims.canonical_dll("KERNEL32.dll"), "kernel32")
        self.assertEqual(shims.canonical_dll("api-ms-win-crt-stdio-l1-1-0.dll"), "ucrtbase")

    def test_runtime_registry(self):
        self.assertIn("WriteFile", shims.supported()["kernel32"])


if __name__ == "__main__":
    unittest.main()
