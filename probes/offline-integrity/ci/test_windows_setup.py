import importlib.util
from pathlib import Path
import tempfile
import unittest
import zipfile

spec=importlib.util.spec_from_file_location('windows_setup',Path(__file__).with_name('windows_setup.py'))
setup=importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)

class DesktopProfile(unittest.TestCase):
 def test_only_client_windows11_arm_is_emulated_compatibility(self):
  env=dict(GITHUB_EVENT_NAME='workflow_dispatch',GITHUB_REPOSITORY='landroval/PackTrace',SOURCE_SHA='a'*40,EXPECTED_SHA='a'*40,VALIDATION_PROFILE='windows11-x64-compat-arm64-v1',REPOSITORY_PRIVATE='false',OWNED_CONFIRMATION='owned-native-fixtures-only')
  facts=dict(major=10,build=26200,product_type=1,native_machine=0xaa64,python_process_machine=0)
  self.assertTrue(setup.compatibility_profile(env,'arm64',facts))
  for key,value in [('major',6),('build',19045),('product_type',3),('native_machine',0x8664)]:
   with self.subTest(key=key),self.assertRaises(ValueError):setup.compatibility_profile(env,'arm64',dict(facts,**{key:value}))
  for key,value in [('EXPECTED_SHA','b'*40),('SOURCE_SHA','bad'),('GITHUB_EVENT_NAME','push'),('REPOSITORY_PRIVATE','true'),('OWNED_CONFIRMATION',''),('VALIDATION_PROFILE','other')]:
   with self.subTest(key=key),self.assertRaises(ValueError):setup.compatibility_profile(dict(env,**{key:value}),'arm64',facts)
  server=dict(env,VALIDATION_PROFILE='windows-scan-amd64-v1',ImageOS='win22')
  self.assertFalse(setup.compatibility_profile(server,'amd64',dict(facts,native_machine=0x8664,product_type=3)))
  with self.assertRaises(ValueError):setup.compatibility_profile(server,'arm64',facts)

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
