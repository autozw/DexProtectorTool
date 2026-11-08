import sys, unittest, tempfile, zipfile, json
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from engine import inputs, decrypt_blocks, signing, recover, RecoveryError, Cancelled
from types import SimpleNamespace

class InputAndFailureTests(unittest.TestCase):
    def test_missing_native(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'base.apk'
            with zipfile.ZipFile(p,'w') as z:z.writestr('classes.dex',b'not native')
            with self.assertRaisesRegex(RecoveryError,'缺少 ARM64'):
                inputs(p,None,lambda:None)

    def test_non_elf_native_is_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'base.apk'
            with zipfile.ZipFile(p,'w') as z:z.writestr('lib/arm64-v8a/libdexprotector.so',b'unknown')
            with self.assertRaisesRegex(RecoveryError,'不是 ELF'):
                inputs(p,None,lambda:None)

    def test_bad_signature_and_directory(self):
        with self.assertRaises(RecoveryError):signing(b'bad zip')
        with self.assertRaises(RecoveryError):decrypt_blocks(bytes(32),bytes(18),SimpleNamespace(expand44=[]),{}, {})

    def test_cancellation_persists_status(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'input.apk';p.write_bytes(b'unused')
            out=Path(t)/'results'
            with self.assertRaises(Cancelled):recover(p,out,cancel=lambda:True)
            reports=list(out.glob('*/manifest.json'))
            self.assertEqual(len(reports),1)
            self.assertEqual(json.loads(reports[0].read_text(encoding='utf-8'))['status'],'cancelled')
            self.assertEqual(list(out.rglob('*.dex')),[])

    def test_failure_keeps_existing_files(self):
        with tempfile.TemporaryDirectory() as t:
            out=Path(t)/'results';out.mkdir();old=out/'keep.dex';old.write_bytes(b'keep')
            p=Path(t)/'bad.apk';p.write_bytes(b'not zip')
            with self.assertRaises(zipfile.BadZipFile):recover(p,out)
            self.assertEqual(old.read_bytes(),b'keep')
            report=next(out.glob('*/manifest.json'))
            self.assertEqual(json.loads(report.read_text(encoding='utf-8'))['status'],'failed')

if __name__=='__main__':unittest.main()
