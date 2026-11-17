"""Repeated fixed-prefix observation for one explicit native text TJ file.

This is not an atomic filesystem or multi-file snapshot. In-place/ABA writes
that evade both observations cannot be excluded. No writer is paused and no
appended suffix is chased or retried.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import stat
from datetime import datetime, timezone
from itertools import islice

from .inputs import InputError, SnapshotReadError, MAX_FILE_BYTES, MAX_EVENTS, MAX_RECORD_BYTES
from .input_files import chain
from .native_tj_stream import Frames


def _open(path):
    if os.name == 'nt':
        from .windows_native import open_shared_read
        opened = open_shared_read(path)
        try:
            # Keep the consenting native handle, but disable buffered read-ahead
            # beyond N. The caller owns and closes the detached raw FileIO.
            return opened.detach()
        except BaseException:
            opened.close()
            raise
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_CLOEXEC', 0)
    return os.fdopen(os.open(path, flags), 'rb', buffering=0)


def _identity(info):
    if not stat.S_ISREG(info.st_mode) or not info.st_ino:
        raise InputError('TJ prefix requires a regular file with an observable identity')
    # Windows file IDs can exceed both signed64 and JavaScript's exact range.
    value = dict(device=str(info.st_dev), inode=str(info.st_ino))
    if hasattr(info, 'st_birthtime_ns'):
        value['birthtime_ns'] = str(info.st_birthtime_ns)
    return value


def _checked(stream, expected, boundary):
    info = os.fstat(stream.fileno())
    if _identity(info) != expected:
        raise SnapshotReadError('TJ prefix handle identity changed', 'source_replaced')
    if info.st_size < boundary:
        raise SnapshotReadError('TJ source was truncated during prefix observation', 'source_truncated')
    return info


def _read(stream, boundary, *, keep):
    remaining = boundary
    checksum = hashlib.sha256()
    parts = []
    while remaining:
        requested = min(65536, remaining)
        block = stream.read(requested)
        if not isinstance(block, bytes) or len(block) > requested:
            raise InputError('invalid bounded TJ prefix stream')
        if not block:
            raise SnapshotReadError('TJ prefix became shorter than its fixed boundary', 'source_truncated')
        remaining -= len(block)
        checksum.update(block)
        if keep:
            parts.append(block)
    return b''.join(parts) if keep else None, checksum.hexdigest()


def _framing(data, max_records, max_record_bytes):
    frames = Frames(io.BytesIO(data), chunk_size=65536, max_input_bytes=MAX_FILE_BYTES, max_record_bytes=max_record_bytes)
    frames.initialize()
    cursor = terminated = frames.start
    tail = None
    count = 0
    iterator = iter(frames)
    try:
        for frame in islice(iterator, max_records):
            count += 1
            cursor = frame['byte_end']
            if frame['terminated']:
                terminated = cursor
            else:
                start = frame['byte_start']
                tail = dict(byte_start=start, byte_end=cursor, bytes=cursor-start,
                    sha256=hashlib.sha256(memoryview(data)[start:cursor]).hexdigest(), open_quote=frame['open_quote'])
    finally:
        iterator.close()
    return dict(boundary_basis='quote_aware_frame_not_valid_event', terminated_prefix_bytes=terminated,
        incomplete_tail=tail, complete_scan=cursor == len(data), unframed_bytes=len(data)-cursor,
        frame_attempts=count, max_records=max_records, max_record_bytes=max_record_bytes)


def read_prefix(path, max_bytes=MAX_FILE_BYTES, *, max_records=MAX_EVENTS, max_record_bytes=MAX_RECORD_BYTES):
    for value, lower, upper in ((max_bytes, 0, MAX_FILE_BYTES), (max_records, 0, MAX_EVENTS), (max_record_bytes, 1, MAX_RECORD_BYTES)):
        if type(value) is not int or not lower <= value <= upper:
            raise InputError('TJ prefix budget outside supported bounds')
    path = Path(path).absolute()
    if '..' in path.parts:
        raise InputError('parent traversal in TJ prefix path')
    started = datetime.now(timezone.utc).isoformat()
    before_chain = chain(path)
    path_identity = _identity(path.lstat())
    with _open(path) as stream:
        first = os.fstat(stream.fileno())
        identity = _identity(first)
        if identity != path_identity:
            raise SnapshotReadError('TJ prefix path changed before opening', 'source_replaced')
        boundary = first.st_size
        if boundary > max_bytes:
            raise SnapshotReadError('TJ prefix exceeds byte limit', 'byte_limit')
        data, checksum = _read(stream, boundary, keep=True)
        sizes = [first.st_size, _checked(stream, identity, boundary).st_size]
        stream.seek(0)
        sizes.append(_checked(stream, identity, boundary).st_size)
        _, repeated = _read(stream, boundary, keep=False)
        sizes.append(_checked(stream, identity, boundary).st_size)
        if checksum != repeated:
            raise SnapshotReadError('TJ prefix bytes changed between observations', 'prefix_changed')
        try:
            final = path.lstat()
            if chain(path) != before_chain or _identity(final) != identity:
                raise InputError('TJ original path no longer names the opened file')
            sizes.append(final.st_size)
        except (OSError, InputError) as exc:
            raise SnapshotReadError('TJ prefix path was replaced or rotated during observation', 'source_replaced') from exc
        if min(sizes) < boundary or any(after < before for before, after in zip(sizes, sizes[1:])):
            raise SnapshotReadError('TJ source was truncated during prefix observation', 'source_truncated')
    fingerprint = dict(method='tj-prefix-v1', file_identity=identity, byte_start=0, byte_end=boundary, sha256=checksum)
    acquisition = dict(fingerprint, snapshot_id=hashlib.sha256(json.dumps(fingerprint, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
        started_at=started, finished_at=datetime.now(timezone.utc).isoformat(), observed_sizes=sizes,
        append_observed=max(sizes)>boundary, excluded_appended_bytes=max(sizes)-boundary,
        atomic_snapshot=False, coherence='two_equal_fixed_prefix_reads_same_observed_file_identity',
        collection_coverage='unknown', writer_protocol='not_verified_against_running_platform',
        limitations=['Appended suffix is outside this snapshot.', 'Repeated byte equality cannot exclude an unobserved in-place rewrite/ABA, later writes, dropped events or a missing node.',
                     'Each file is observed separately; no atomic multi-file snapshot or database/run ownership is established.'],
        framing=_framing(data, max_records, max_record_bytes))
    return data, acquisition
