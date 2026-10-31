import importlib.util
from pathlib import Path
import tempfile
import unittest
import zipfile

spec=importlib.util.spec_from_file_location('windows_setup',Path(__file__).with_name('windows_setup.py'))
setup=importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)

class SDKExtraction(unittest.TestCase):
 def test_archive_paths_and_types_never_escape(self):
  for path in ('../outside','/go/a','go/../outside','go/a/../../b','go/a\\b','go/C:a','go//a','other/file','go/./a','go/NUL','go/COM1.txt','go/file.','go/a?b'):
   with self.subTest(path=path),self.assertRaises(ValueError):setup.archive_name(path)
  self.assertEqual(setup.archive_name('go/bin/go.exe'),('go','bin','go.exe'))
  with tempfile.TemporaryDirectory()as d:
   root=Path(d);z=root/'sdk.zip'
   with zipfile.ZipFile(z,'w')as f:
    entry=zipfile.ZipInfo('go/link');entry.external_attr=(0o120777<<16);f.writestr(entry,'outside')
   with self.assertRaises(ValueError):setup.extract(z,root/'out')
   self.assertFalse((root/'out/go/link').exists())
 def test_exact_regular_bytes_and_case_collision(self):
  with tempfile.TemporaryDirectory()as d:
   root=Path(d);z=root/'sdk.zip';out=root/'out'
   with zipfile.ZipFile(z,'w')as f:f.writestr('go/bin/go.exe',b'owned')
   self.assertEqual(setup.extract(z,out),5)
   self.assertEqual((out/'go/bin/go.exe').read_bytes(),b'owned')
   with zipfile.ZipFile(z,'w')as f:
    f.writestr('go/bin/Go.exe',b'a');f.writestr('go/bin/go.exe',b'b')
   with self.assertRaises(ValueError):setup.extract(z,root/'collision')

if __name__=='__main__':unittest.main()
