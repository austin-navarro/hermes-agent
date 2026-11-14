"""Bounded retries for Telegram's read-only file metadata/download requests.

Port the timeout retry used by image intake (89bcdc7b) to all media readers;
no CRM operation or message send belongs in this loop.
"""
import asyncio
from typing import Any


async def retrieve_media_bytes(source: Any) -> tuple[Any, bytearray]:
    from telegram.error import TimedOut

    for attempt in range(3):
        try:
            file_obj = await source.get_file()
            return file_obj, await file_obj.download_as_bytearray()
        except TimedOut:
            if attempt == 2:
                raise
            await asyncio.sleep(0.1)
    raise RuntimeError("Telegram media retry state was exhausted")
