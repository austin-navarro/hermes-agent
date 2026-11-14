"""Transient Telegram reads retry; quoted voice preserves automatic STT routing."""
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from telegram.error import BadRequest, TimedOut
from gateway.platforms.base import CachedMedia
from gateway.platforms.event import MessageEvent, MessageType
from gateway.run import _event_media_is_stt_input
from plugins.platforms.telegram import adapter as tg
from plugins.platforms.telegram.adapter import TelegramAdapter


@pytest.mark.asyncio
@pytest.mark.parametrize("voice", [True, False])
async def test_quoted_voice_is_stt_input_but_audio_file_is_not(voice, tmp_path):
    adapter = object.__new__(TelegramAdapter)
    cached = CachedMedia(str(tmp_path / "clip.ogg"), "audio/ogg", "audio", "voice.ogg")
    adapter._download_observed_media = AsyncMock(return_value=("ok", cached))
    reply = SimpleNamespace(voice=object() if voice else None)
    event = MessageEvent(text="Read this recording")
    await adapter._cache_replied_media(SimpleNamespace(reply_to_message=reply), event)
    assert event.message_type == (MessageType.VOICE if voice else MessageType.AUDIO)
    assert _event_media_is_stt_input(event, 0) is voice
    assert event.media_urls == [cached.path]


@pytest.mark.asyncio
@pytest.mark.parametrize("phase", ["metadata", "download"])
async def test_voice_get_file_timeout_retries_and_caches_once(monkeypatch, phase):
    adapter = object.__new__(TelegramAdapter)
    adapter._telegram_media_size_allowed = lambda *args: (True, None)
    adapter._surface_media_cache_failure = AsyncMock()
    file = SimpleNamespace(download_as_bytearray=AsyncMock(return_value=bytearray(b"voice")))
    replies = [TimedOut(), file] if phase == "metadata" else [file, file]
    if phase == "download":
        file.download_as_bytearray.side_effect = [TimedOut(), bytearray(b"voice")]
    source = SimpleNamespace(file_name=None, get_file=AsyncMock(side_effect=replies))
    cache = AsyncMock(return_value="/owned/voice.ogg")
    monkeypatch.setattr(tg, "cache_audio_from_bytes_async", cache)
    monkeypatch.setattr("asyncio.sleep", AsyncMock())
    event = MessageEvent(text="", message_type=MessageType.VOICE)
    await adapter._cache_inbound_av(object(), event, source, "voice message", "voice", ".ogg", "audio/ogg")
    assert source.get_file.await_count == 2
    assert event.media_urls == ["/owned/voice.ogg"]
    cache.assert_awaited_once()
    adapter._surface_media_cache_failure.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("error,attempts", [(TimedOut(), 3), (BadRequest("invalid synthetic file"), 1)])
async def test_retry_is_bounded_and_permanent_error_is_not_retried(error, attempts, monkeypatch):
    adapter = object.__new__(TelegramAdapter)
    adapter._telegram_media_size_allowed = lambda *args: (True, None)
    adapter._surface_media_cache_failure = AsyncMock()
    source = SimpleNamespace(file_name=None, get_file=AsyncMock(side_effect=error))
    monkeypatch.setattr("asyncio.sleep", AsyncMock())
    event = MessageEvent(text="", message_type=MessageType.VOICE)
    await adapter._cache_inbound_av(object(), event, source, "voice message", "voice", ".ogg", "audio/ogg")
    assert source.get_file.await_count == attempts
    assert event.media_urls == []
    adapter._surface_media_cache_failure.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("key", ["platforms/telegram", "telegram-platform"])
async def test_profile_override_is_loaded_by_native_discovery_and_routes_voice(tmp_path, monkeypatch, key):
    import shutil
    from pathlib import Path
    from hermes_cli import plugins
    from gateway.config import PlatformConfig
    from gateway.platform_registry import platform_registry

    home = tmp_path / "profile"
    target = home / "plugins" / key
    source = Path(__file__).resolve().parents[4] / "plugins" / "platforms" / "telegram"
    shutil.copytree(source, target, ignore=shutil.ignore_patterns("__pycache__"))
    (home / "config.yaml").write_text(f"plugins:\n  enabled:\n    - {key}\n")
    monkeypatch.setenv("HERMES_HOME", str(home))
    manager = plugins.PluginManager()
    manager.discover_and_load()
    loaded = manager._plugins[key]
    assert loaded.enabled and loaded.error is None and loaded.manifest.source == "user"
    assert Path(loaded.manifest.path) == target
    entry = platform_registry.get("telegram")
    adapter = entry.adapter_factory(PlatformConfig(enabled=True))
    assert Path(adapter._cache_replied_media.__func__.__code__.co_filename).is_relative_to(target)
    cached = CachedMedia(str(tmp_path / "voice.ogg"), "audio/ogg", "audio", "voice.ogg")
    adapter._download_observed_media = AsyncMock(return_value=("ok", cached))
    event = MessageEvent(text="read this voice")
    await adapter._cache_replied_media(SimpleNamespace(reply_to_message=SimpleNamespace(voice=object())), event)
    assert _event_media_is_stt_input(event, 0)
