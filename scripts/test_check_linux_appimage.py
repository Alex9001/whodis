"""Offline regression tests for the packaged ELF compatibility audit."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('linux_appimage', Path(__file__).with_name('check-linux-appimage.py'))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class ElfAuditTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'AppDir'
        self.root.mkdir()
        self.report = Path(self.temp.name) / 'elf-audit.json'
        for number in range(11):
            (self.root / str(number)).write_bytes(b'\x7fELFfixture')
        self.dynamic = ('Dynamic section at offset 0x10\n'
                        ' (NEEDED) Shared library: [libc.so.6]\n'
                        ' (RUNPATH) Library runpath: [$ORIGIN/../lib]')
        self.symbols = ('0000 *UND* (GLIBC_2.35) libc_entry\n'
                        '0000 *UND* (GLIBCXX_3.4.30) std_entry\n'
                        '0000 *UND* (CXXABI_1.3.13) abi_entry')
        self.libraries = 'libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x0)'

    def command_output(self, *args, **kwargs):
        return {'readelf': self.dynamic, 'objdump': self.symbols, 'ldd': self.libraries}[args[0]]

    def audit(self):
        with patch.object(checker, 'output', side_effect=self.command_output):
            return checker.inspect_elf(self.root, self.report)

    def test_baseline_symbols_and_relative_paths(self):
        self.assertEqual(self.audit(), 11)
        self.assertIn('libc.so.6', self.report.read_text())

    def test_too_new_symbol_families(self):
        for family, version in [('GLIBC', '2.36'), ('GLIBCXX', '3.4.31'), ('CXXABI', '1.3.14')]:
            self.symbols = f'0000 *UND* ({family}_{version}) entry'
            with self.subTest(family=family), self.assertRaisesRegex(ValueError, 'symbol limit'):
                self.audit()

    def test_defined_symbols_do_not_raise_required_baseline(self):
        self.symbols = '0000 .text (GLIBC_9.99) locally_defined'
        self.assertEqual(self.audit(), 11)

    def test_static_executables_need_no_dynamic_table(self):
        def static_output(*args, **kwargs):
            self.assertEqual(args[0], 'readelf')
            return 'There is no dynamic section in this file.'
        with patch.object(checker, 'output', side_effect=static_output):
            self.assertEqual(checker.inspect_elf(self.root, self.report), 11)

    def test_missing_library_rejected(self):
        self.libraries = 'libQt6Core.so.6 => not found'
        with self.assertRaisesRegex(ValueError, 'Unresolved dependency'):
            self.audit()

    def test_nonrelocatable_and_empty_rpaths_rejected(self):
        for runtime_path in ('/home/builder/qt/lib', '/usr/local/lib', '', '$ORIGIN:', 'relative/lib'):
            self.dynamic = f'Dynamic section at offset 0x10\n (RUNPATH) Library runpath: [{runtime_path}]'
            with self.subTest(path=runtime_path), self.assertRaisesRegex(ValueError, 'runtime path'):
                self.audit()

    def test_braced_origin_rpath_supported(self):
        self.dynamic = 'Dynamic section at offset 0x10\n (RPATH) Library rpath: [${ORIGIN}/../lib]'
        self.assertEqual(self.audit(), 11)

    def test_dependency_outside_package_system_roots_rejected(self):
        self.libraries = 'libQt6Core.so.6 => /opt/Qt/lib/libQt6Core.so.6 (0x0)'
        with self.assertRaisesRegex(ValueError, 'outside package/system'):
            self.audit()

    def test_bundled_dependency_supported(self):
        library = self.root / 'usr/lib/libQt6Core.so.6'
        library.parent.mkdir(parents=True)
        library.write_bytes(b'fixture library')
        self.libraries = f'libQt6Core.so.6 => {library} (0x0)'
        self.assertEqual(self.audit(), 11)

    def test_elf_symlink_escape_rejected(self):
        external = Path(self.temp.name) / 'external'
        external.write_bytes(b'\x7fELFexternal')
        (self.root / 'escape').symlink_to(external)
        with self.assertRaisesRegex(ValueError, 'symlink escapes'):
            self.audit()

    def test_implausibly_small_bundle_rejected(self):
        for number in range(1, 11):
            (self.root / str(number)).unlink()
        with self.assertRaisesRegex(ValueError, 'Unexpectedly few'):
            self.audit()


if __name__ == '__main__':
    unittest.main()
