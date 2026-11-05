"""Optional payload discovery is isolated only for the child_env fixture lifetime."""
from pathlib import Path
import json

import pytest

from pm import environments
from tests.tools import _child_env_fixtures


child_env = _child_env_fixtures.child_env
_ORIGINAL_PAYLOAD_READER = environments._payload_manifest


def test_child_env_payload_lookup_does_not_probe_files(child_env, monkeypatch):
    checkout = child_env / 'checkout'
    checkout.mkdir()
    reads = []
    original = Path.read_text

    def record(path, *args, **kwargs):
        reads.append(str(path))
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, 'read_text', record)
    assert environments._payload_manifest(checkout) is None
    assert reads == [], {'unexpected_payload_probes': reads}


def test_child_env_payload_patch_restores_original_reader(child_env, tmp_path, monkeypatch):
    nested = tmp_path / 'nested'
    nested.mkdir()
    checkout = nested / 'checkout'
    checkout.mkdir()
    payload = {'repo': 'checkout'}
    (nested / 'manifest.json').write_text(json.dumps(payload))
    # Model the real generator fixture and its monkeypatch teardown, not a
    # duplicate implementation. Genuine-reader/guard controls live in cron's
    # existing isolation module and are run alongside these checks.
    with monkeypatch.context() as outer:
        outer.setattr(environments, '_payload_manifest', _ORIGINAL_PAYLOAD_READER)
        with pytest.MonkeyPatch.context() as local:
            setup = _child_env_fixtures.child_env.__wrapped__
            lifetime = setup(local, nested)
            try:
                assert next(lifetime) == nested
                assert environments._payload_manifest is not _ORIGINAL_PAYLOAD_READER
                assert environments._payload_manifest(checkout) is None
            finally:
                lifetime.close()
        assert environments._payload_manifest is _ORIGINAL_PAYLOAD_READER
        assert environments._payload_manifest(checkout) == (payload, nested)
    assert environments._payload_manifest is not _ORIGINAL_PAYLOAD_READER
