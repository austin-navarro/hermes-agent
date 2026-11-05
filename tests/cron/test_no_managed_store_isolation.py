"""Cron's no-host-store fixture must also isolate optional payload discovery.

Capture the genuine reader at collection, before the per-test fixture patches it.
All reader inputs and guard probes below are synthetic, test-owned paths.
"""
import io
import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from pm import environments
from tests.cron.conftest import _no_managed_store
from tests.home_io_guard import HomeIOGuard


_ORIGINAL_PAYLOAD_READER = environments._payload_manifest


def test_cron_payload_lookup_is_nonpayload_without_file_reads(tmp_path, monkeypatch):
    checkout = tmp_path / 'checkout'
    checkout.mkdir()
    reads = []
    original = Path.read_text

    def record(path, *args, **kwargs):
        reads.append(str(path))
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, 'read_text', record)
    assert environments._payload_manifest(checkout) is None
    assert reads == [], {'unexpected_payload_probes': reads}


@pytest.mark.parametrize('placement', ['parent', 'inplace'])
def test_genuine_payload_reader_still_reads_temporary_payload(tmp_path, placement):
    checkout = tmp_path / 'tree'
    checkout.mkdir()
    payload = {
        'repo': 'tree' if placement == 'parent' else '.',
        'venv': 'venv',
        'store': 'store',
        'runtime': {'commands': {'hermes': 'bin/hermes'}},
    }
    parent = tmp_path if placement == 'parent' else checkout
    (parent / 'manifest.json').write_text(json.dumps(payload))
    assert _ORIGINAL_PAYLOAD_READER(checkout) == (payload, parent)
    assert environments._payload_manifest(checkout) is None


@pytest.mark.parametrize('content', [None, '{invalid', '{"repo": 7}'])
def test_genuine_payload_reader_still_rejects_temporary_nonpayload(tmp_path, content):
    checkout = tmp_path / 'tree'
    checkout.mkdir()
    if content is not None:
        (tmp_path / 'manifest.json').write_text(content)
    assert _ORIGINAL_PAYLOAD_READER(checkout) is None


def test_home_io_guard_refuses_before_underlying_open(tmp_path, monkeypatch):
    protected_home = tmp_path / 'synthetic-protected-home'
    protected_home.mkdir()
    underlying = Mock(side_effect=AssertionError('underlying open must not run'))
    with monkeypatch.context() as local:
        local.setattr(io, 'open', underlying)
        HomeIOGuard(lambda: [protected_home]).install(local)
        # Probe the installed io.open guard, not the distinct builtin open entrypoint.
        guarded_io_open = io.open
        with pytest.raises(AssertionError, match='REAL hermes home'):
            guarded_io_open(protected_home / 'never-opened-manifest.json')
        underlying.assert_not_called()


def test_payload_discovery_patch_is_scoped_and_restores_genuine_reader(tmp_path, monkeypatch):
    checkout = tmp_path / 'tree'
    checkout.mkdir()
    payload = {'repo': 'tree'}
    (tmp_path / 'manifest.json').write_text(json.dumps(payload))
    # Exercise the actual fixture's setup/undo contract inside nested contexts;
    # never call the mock itself as evidence of genuine-reader behavior.
    with monkeypatch.context() as outer:
        outer.setattr(environments, '_payload_manifest', _ORIGINAL_PAYLOAD_READER)
        with pytest.MonkeyPatch.context() as local:
            _no_managed_store.__wrapped__(tmp_path, local)
            assert environments._payload_manifest is not _ORIGINAL_PAYLOAD_READER
            assert environments._payload_manifest(checkout) is None
        assert environments._payload_manifest is _ORIGINAL_PAYLOAD_READER
        assert environments._payload_manifest(checkout) == (payload, tmp_path)
    assert environments._payload_manifest is not _ORIGINAL_PAYLOAD_READER
