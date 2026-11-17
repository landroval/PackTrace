"""Run with: python -m unittest discover -s docs/windows-smoke-guide -v"""
import re
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path

from render import NAMES, SOURCE, render


class GuideTest(unittest.TestCase):
    def test_artifacts_and_copy_safe_blocks(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "guide"
            render(output)
            blocks = re.findall(r"```powershell\n(.*?)```", SOURCE.read_text(), re.S)
            for name, block in zip(NAMES, blocks):
                data = (output / name).read_bytes()
                self.assertTrue(data.startswith(b"\xef\xbb\xbf"))
                self.assertEqual(data.decode("utf-8-sig").replace("\r\n", "\n"), block)
                self.assertNotIn("`\n", block)
                # Every statement/entry boundary is explicit, not a newline.
                for line in block.splitlines():
                    self.assertTrue(line.rstrip().endswith((";", "@{")), line)
            pdf = next(output.glob("*.pdf"))
            self.assertTrue(pdf.read_bytes().startswith(b"%PDF-"))
            text = subprocess.check_output(["pdftotext", "-layout", str(pdf), "-"], text=True)
            for name in NAMES:
                self.assertIn(name, text)
            self.assertIn("81ab676295f1b9df982d6754a9faf040144fa0f9e0c5746e8c449b8a5a6bd0fd", text)
            self.assertIn("packageManager='npm@9.9.4';", text)
            self.assertIn("} };", text)
            with self.assertRaises(FileExistsError):
                render(output)
            scripts = Path(temporary) / "scripts-only"
            render(scripts, scripts_only=True)
            self.assertFalse(list(scripts.glob("*.pdf")))
            for path in scripts.iterdir():
                self.assertEqual(path.read_bytes(), (output / path.name).read_bytes())
            bundle = SOURCE.with_name("PackTrace-Windows-Guia-corregida-r1.zip")
            with zipfile.ZipFile(bundle) as archive:
                for path in scripts.iterdir():
                    self.assertEqual(archive.read(path.name), path.read_bytes())
                self.assertEqual(archive.read(pdf.name), SOURCE.with_name(pdf.name).read_bytes())
            if shutil.which("pwsh"):
                subprocess.run(["pwsh", "-NoProfile", "-File", str(output / "verify-samples.ps1")], check=True)
            else:
                print("PowerShell unavailable: parser checks NOT executed; use verify-samples.ps1 on Windows 5.1.")


if __name__ == "__main__":
    unittest.main()
