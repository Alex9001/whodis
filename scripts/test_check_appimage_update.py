"""Offline regression tests for the release AppImage/zsync validation gate."""
import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('appimage_update', Path(__file__).with_name('check-appimage-update.py'))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class UpdateVerificationTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.image = Path(self.temp.name) / 'whodis-gui-2.5.4-x86_64.AppImage'
        self.image.write_bytes(b'Whodis fixture payload')
        self.fields = {
            'zsync': '0.6.2', 'Filename': self.image.name, 'MTime': 'Thu, 01 Oct 2026 00:00:00 +0000',
            'Blocksize': '2048', 'Length': str(self.image.stat().st_size),
            'Hash-Lengths': '1,2,4', 'URL': self.image.name,
            'SHA-1': hashlib.sha1(self.image.read_bytes()).hexdigest(),
        }
        self.write_sidecar()

    def write_sidecar(self, blocks=b'123456', extra=''):
        self.image.with_name(self.image.name + '.zsync').write_bytes(
            ('\n'.join(f'{key}: {value}' for key, value in self.fields.items()) + extra + '\n\n').encode() + blocks)

    def test_stable_architecture_channels(self):
        for arch in ('x86_64', 'aarch64'):
            channel = checker.stable_channel(Path(f'whodis-gui-2.5.4-{arch}.AppImage'))
            self.assertEqual(channel, f'gh-releases-zsync|Alex9001|whodis|latest|whodis-gui-*-{arch}.AppImage.zsync')

    def test_nonstable_and_legacy_names_rejected(self):
        for name in ('whodis-gui-2.5.4-rc1-x86_64.AppImage', 'whodis-gui_linux_amd64.AppImage', 'whodis-gui-2.5.4-arm64.AppImage'):
            with self.subTest(name=name), self.assertRaises(checker.VerificationError):
                checker.stable_channel(Path(name))

    def test_valid_header(self):
        self.assertEqual(checker.verify_sidecar(self.image).name, self.image.name + '.zsync')

    def test_identity_mismatches(self):
        for key, value in [('Filename', 'wrong.AppImage'), ('URL', '../wrong.AppImage'), ('Length', '999'), ('SHA-1', '0' * 40)]:
            with self.subTest(key=key):
                original = self.fields[key]
                self.fields[key] = value
                self.write_sidecar()
                with self.assertRaises(checker.VerificationError):
                    checker.verify_sidecar(self.image)
                self.fields[key] = original

    def test_bad_block_table(self):
        for blocks in (b'', b'12345', b'1234567'):
            self.write_sidecar(blocks)
            with self.assertRaises(checker.VerificationError):
                checker.verify_sidecar(self.image)

    def test_duplicate_header(self):
        self.write_sidecar(extra='\nURL: ' + self.image.name)
        with self.assertRaises(checker.VerificationError):
            checker.verify_sidecar(self.image)

    def test_missing_and_invalid_fields(self):
        for field, value in [('Hash-Lengths', '1,9,4'), ('Hash-Lengths', '1,2'), ('Blocksize', '0'), ('Blocksize', '3'), ('Length', 'oops')]:
            original = self.fields[field]
            self.fields[field] = value
            self.write_sidecar()
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                checker.verify_sidecar(self.image)
            self.fields[field] = original
        del self.fields['SHA-1']
        self.write_sidecar()
        with self.assertRaises(checker.VerificationError):
            checker.verify_sidecar(self.image)

    def reconstruct(self, args, **kwargs):
        shutil.copyfile(self.image, args[args.index('-o') + 1])

    def test_full_gate_and_runtime_environment(self):
        channel = checker.stable_channel(self.image)
        with patch.dict(os.environ, {'APPIMAGE_EXTRACT_AND_RUN': '1'}), \
             patch.object(checker.subprocess, 'check_output', return_value=channel + '\n') as query, \
             patch.object(checker.subprocess, 'run', side_effect=self.reconstruct) as reconstruction:
            checker.verify(self.image)
            self.assertNotIn('APPIMAGE_EXTRACT_AND_RUN', query.call_args.kwargs['env'])
            self.assertEqual(query.call_args.args[0][-1], '--appimage-updateinformation')
            self.assertTrue(reconstruction.call_args.kwargs['check'])

    def test_explicit_channel(self):
        with patch.object(checker.subprocess, 'check_output', return_value='custom-channel'), \
             patch.object(checker.subprocess, 'run', side_effect=self.reconstruct):
            checker.verify(self.image, 'custom-channel')

    def test_wrong_channel_stops_before_reconstruction(self):
        with patch.object(checker.subprocess, 'check_output', return_value='wrong'), \
             patch.object(checker.subprocess, 'run') as reconstruction:
            with self.assertRaises(checker.VerificationError):
                checker.verify(self.image)
            reconstruction.assert_not_called()

    @unittest.skipUnless(shutil.which('zsync') and shutil.which('zsyncmake'),
                         'zsync and zsyncmake are required for real reconstruction')
    def test_real_zsync_reconstruction(self):
        channel = checker.stable_channel(self.image)
        self.image.write_text('#!/bin/sh\n' + "printf '%s\\n' '" + channel + "'\n" +
                              '# Payload padding\n' * 300)
        self.image.chmod(0o755)
        subprocess.run(['zsyncmake', '-u', self.image.name, '-o', self.image.name + '.zsync',
                        self.image.name], cwd=self.image.parent, check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        checker.verify(self.image)

    def test_reconstruction_failure_and_mismatch(self):
        for failure in (True, False):
            def reconstruct(args, **kwargs):
                if failure:
                    raise subprocess.CalledProcessError(1, args)
                Path(args[args.index('-o') + 1]).write_bytes(b'wrong bytes')
            with patch.object(checker.subprocess, 'check_output', return_value=checker.stable_channel(self.image)), \
                 patch.object(checker.subprocess, 'run', side_effect=reconstruct):
                with self.assertRaises((checker.VerificationError, subprocess.CalledProcessError)):
                    checker.verify(self.image)


if __name__ == '__main__':
    unittest.main()
