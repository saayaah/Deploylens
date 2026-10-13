"""Safe ZIP inspection. Validates archive structure before any content is read.

Nothing is extracted to disk and no uploaded code is executed. Entries are
read in memory with per-file size caps.
"""
from __future__ import annotations

import io
import posixpath
import stat
import zipfile
from dataclasses import dataclass

MAX_ARCHIVE_BYTES = 20 * 1024 * 1024        # compressed upload size
MAX_FILES = 2000                             # entries processed
MAX_TOTAL_UNCOMPRESSED = 100 * 1024 * 1024   # sum of declared sizes
MAX_FILE_BYTES = 1 * 1024 * 1024             # per text file read for analysis
MAX_COMPRESSION_RATIO = 100                  # guards zip bombs


class ArchiveError(Exception):
    """Base class for rejected uploads. Message is safe to show to users."""


class UnsafeArchiveError(ArchiveError):
    pass


class ArchiveLimitError(ArchiveError):
    pass


@dataclass(frozen=True)
class ArchiveEntry:
    path: str
    size: int


def _is_unsafe_name(name: str) -> bool:
    if not name or "\x00" in name or "\\" in name:
        return True
    if name.startswith("/") or (len(name) > 1 and name[1] == ":"):
        return True
    parts = name.split("/")
    if any(p == ".." for p in parts):
        return True
    normalized = posixpath.normpath(name)
    return normalized.startswith("..") or normalized.startswith("/")


def validate_archive(data: bytes) -> list[ArchiveEntry]:
    """Validate a ZIP payload and return safe, regular file entries.

    Raises ArchiveError subclasses for invalid or unsafe archives.
    """
    if len(data) > MAX_ARCHIVE_BYTES:
        raise ArchiveLimitError(
            f"Archive exceeds the {MAX_ARCHIVE_BYTES // (1024 * 1024)} MB upload limit."
        )
    if not data:
        raise ArchiveError("Uploaded file is empty.")
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise ArchiveError("Uploaded file is not a valid ZIP archive.") from exc

    with zf:
        infos = zf.infolist()
        if len(infos) > MAX_FILES * 2:
            # Hard ceiling on raw entries, including directories.
            raise ArchiveLimitError("Archive contains too many entries.")

        entries: list[ArchiveEntry] = []
        total = 0
        for info in infos:
            name = info.filename
            if _is_unsafe_name(name):
                raise UnsafeArchiveError(f"Unsafe path rejected in archive: {name!r}")

            mode = (info.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(mode):
                raise UnsafeArchiveError(f"Symbolic link rejected in archive: {name!r}")

            if info.is_dir():
                continue

            if info.file_size > 0 and info.compress_size > 0:
                ratio = info.file_size / info.compress_size
                if ratio > MAX_COMPRESSION_RATIO:
                    raise UnsafeArchiveError(
                        f"Suspicious compression ratio for {name!r}; possible zip bomb."
                    )

            total += info.file_size
            if total > MAX_TOTAL_UNCOMPRESSED:
                raise ArchiveLimitError("Archive expands beyond the uncompressed size limit.")

            entries.append(ArchiveEntry(path=posixpath.normpath(name), size=info.file_size))
            if len(entries) > MAX_FILES:
                raise ArchiveLimitError(f"Archive contains more than {MAX_FILES} files.")

        if not entries:
            raise ArchiveError("Archive contains no files.")
        return entries


def read_entries(data: bytes, entries: list[ArchiveEntry]) -> dict[str, bytes]:
    """Read the validated entries into memory, skipping files over the per-file cap."""
    out: dict[str, bytes] = {}
    wanted = {e.path for e in entries}
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for info in zf.infolist():
            name = posixpath.normpath(info.filename)
            if info.is_dir() or name not in wanted:
                continue
            if info.file_size > MAX_FILE_BYTES:
                out[name] = b""  # present but too large to inspect; rules treat as unreadable
                continue
            out[name] = zf.read(info)
    return out
