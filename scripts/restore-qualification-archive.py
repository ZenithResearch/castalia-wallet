"""Restore a digest-pinned test package; links, traversal and oversized data fail."""
from pathlib import Path
import hashlib
import re
import sys
import tarfile

def require(condition, message):
    if not condition:
        raise ValueError(message)

archive, expected, destination = sys.argv[1:]
require(re.fullmatch(r"[a-f0-9]{64}", expected), "invalid archive digest")
require(Path(archive).stat().st_size <= 128 * 1024 * 1024, "archive too large")
require(hashlib.sha256(Path(archive).read_bytes()).hexdigest() == expected, "archive digest mismatch")
root = Path(destination)
require(not root.exists(), "destination already exists")
with tarfile.open(archive) as source:
    seen = set()
    size = 0
    for member in source:
        path = Path(member.name)
        require(not path.is_absolute() and ".." not in path.parts, "unsafe archive path")
        require(member.isfile() or member.isdir(), "unsupported archive entry")
        require(not member.issym() and not member.islnk(), "archive links forbidden")
        require(str(path) not in seen, "duplicate archive entry")
        seen.add(str(path))
        size += member.size
        require(size <= 128 * 1024 * 1024 and len(seen) <= 1000, "archive limits exceeded")
    root.mkdir(mode=0o700)
    source.extractall(root, filter="data")
