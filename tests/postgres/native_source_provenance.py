"""Fail-closed source/copy/grant identity for owned native launchers."""

import hashlib

_UNSET = object()


def _hashes(root, tracked):
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            for name in tracked}


def verify_source_copy(source, copied, tracked, *, granted=_UNSET):
    source_hashes = _hashes(source, tracked)
    copied_hashes = _hashes(copied, tracked)
    if copied_hashes != source_hashes:
        raise RuntimeError('copied source differs from the reviewed source inventory')
    if granted is not _UNSET and granted != source_hashes:
        raise RuntimeError('grant source inventory differs from the reviewed source inventory')
    return source_hashes
