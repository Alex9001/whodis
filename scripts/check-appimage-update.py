#!/usr/bin/env python3
"""Verify a Whodis AppImage's update channel and matching zsync sidecar.

Stable images use the architecture-specific GitHub latest channel by default.
Pass --expected-channel explicitly when validating a different release channel.
Requires zsync, and executes only the AppImage runtime's metadata query.
"""
import argparse
import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


class VerificationError(ValueError):
    """The image or sidecar does not satisfy the release contract."""


def require(condition, message):
    if not condition:
        raise VerificationError(message)


def digest(path, algorithm):
    result = hashlib.new(algorithm)
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def stable_channel(appimage):
    match = re.fullmatch(r'whodis-gui-[0-9]+\.[0-9]+\.[0-9]+-(x86_64|aarch64)\.AppImage', appimage.name)
    require(match is not None, 'Expected a stable whodis-gui-X.Y.Z-{x86_64,aarch64}.AppImage filename; use --expected-channel for other channels')
    return f'gh-releases-zsync|Alex9001|whodis|latest|whodis-gui-*-{match.group(1)}.AppImage.zsync'


def verify_sidecar(appimage):
    sidecar = appimage.with_name(appimage.name + '.zsync')
    content = sidecar.read_bytes()
    require(b'\n\n' in content, 'Missing zsync header separator')
    header, blocks = content.split(b'\n\n', 1)
    fields = {}
    for line in header.decode('utf-8').splitlines():
        require(': ' in line, 'Malformed zsync header line')
        key, value = line.split(': ', 1)
        require(key not in fields, f'Duplicate zsync field: {key}')
        fields[key] = value
    for key in ('zsync', 'Filename', 'URL', 'Length', 'SHA-1', 'Blocksize', 'Hash-Lengths'):
        require(key in fields, f'Missing zsync field: {key}')
    require(fields['Filename'] == appimage.name, 'zsync Filename does not match image')
    require(fields['URL'] == appimage.name, 'zsync URL must be the image basename')
    length = appimage.stat().st_size
    require(int(fields['Length']) == length, 'zsync Length does not match image')
    require(fields['SHA-1'] == digest(appimage, 'sha1'), 'zsync SHA-1 does not match image')
    blocksize = int(fields['Blocksize'])
    hashes = [int(value) for value in fields['Hash-Lengths'].split(',')]
    require(blocksize > 0 and blocksize & (blocksize - 1) == 0, 'Invalid zsync Blocksize')
    require(len(hashes) == 3, 'Invalid zsync Hash-Lengths')
    sequence, weak, strong = hashes
    require(sequence in (1, 2) and 1 <= weak <= 4 and 1 <= strong <= 16, 'Invalid zsync hash lengths')
    expected_bytes = ((length + blocksize - 1) // blocksize) * (weak + strong)
    require(length > 0 and len(blocks) == expected_bytes, 'Missing or truncated zsync block checksums')
    return sidecar


def verify(appimage, expected_channel=None):
    appimage = Path(appimage).resolve()
    require(appimage.is_file(), f'Image does not exist: {appimage}')
    expected_channel = expected_channel or stable_channel(appimage)
    environment = {key: value for key, value in os.environ.items() if key != 'APPIMAGE_EXTRACT_AND_RUN'}
    actual = subprocess.check_output(
        [str(appimage), '--appimage-updateinformation'], text=True,
        env=environment, timeout=30).strip()
    require(actual == expected_channel, f'Unexpected update channel: {actual!r}; expected {expected_channel!r}')
    sidecar = verify_sidecar(appimage)
    with tempfile.TemporaryDirectory(prefix='whodis-zsync-') as temporary:
        rebuilt = Path(temporary) / appimage.name
        # A complete matching seed avoids downloading anything. zsync still
        # checks its block table and final checksum before producing the file.
        subprocess.run(['zsync', '-i', str(appimage), '-o', str(rebuilt), str(sidecar)],
                       check=True, cwd=temporary, timeout=120)
        require(rebuilt.is_file(), 'zsync did not produce a reconstructed image')
        require(rebuilt.stat().st_size == appimage.stat().st_size and
                digest(rebuilt, 'sha256') == digest(appimage, 'sha256'),
                'zsync reconstruction differs from image')
    print(f'Verified update channel and zsync reconstruction: {appimage.name}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('appimage', type=Path)
    parser.add_argument('--expected-channel')
    args = parser.parse_args()
    try:
        verify(args.appimage, args.expected_channel)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f'AppImage update verification failed: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
