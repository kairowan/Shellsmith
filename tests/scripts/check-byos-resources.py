#!/usr/bin/env python3
"""核对真正分发的三个 ZIP，拒绝授权模式或 Google 依赖混入错误产物。"""
import json
from pathlib import Path
import sys
import zipfile

root = Path(__file__).resolve().parents[2]
resources = Path(sys.argv[1]) if len(sys.argv) > 1 else root / 'shield-stub/build/outputs/resources'
for filename, mode, play in [('resources.zip', None, False), ('resources-byos.zip', 'device_approval', False), ('resources-byos-play.zip', 'play_integrity', True)]:
    with zipfile.ZipFile(resources / filename) as archive:
        metadata = json.loads(archive.read('metadata.json'))
        dex = archive.read('stub-classes.dex')
        assert dex.startswith(b'dex\n'), filename
        assert bool(metadata.get('byos_remote_key')) == bool(mode), filename
        assert bool(metadata.get('risk_events_v1')) == (mode == 'device_approval'), filename
        if mode:
            assert metadata['byos_auth'] == mode and metadata['byos_fetch_protocol'] == 2, filename
            assert metadata['min_android_api'] == (29 if play else 24), filename
        assert (b'com.google.android.play.core.integrityservice.BIND_INTEGRITY_SERVICE' in dex) == play, filename
        assert b'Lcom/google/android/' not in dex, filename
        for marker in (b'shellsmith-risk-event-v1', b'/v1/risk-events/challenge', b'/v1/risk-events/report'):
            assert (marker in dex) == (mode == 'device_approval'), (filename, marker)
        for abi in ('arm64-v8a', 'armeabi-v7a', 'x86', 'x86_64'):
            assert archive.read(f'lib/{abi}/libmocikashield.so').startswith(b'\x7fELF'), filename
    print(f'{filename}: OK')
config = json.loads((root / 'apps/shield-gui/src-tauri/tauri.conf.json').read_text())
for name in ('resources-byos.zip', 'resources-byos-play.zip'):
    assert f'resources/{name}' in config['bundle']['resources'].values(), name
