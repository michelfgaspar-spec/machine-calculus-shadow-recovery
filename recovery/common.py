"""Path, JSON and digest utilities derived from the original builder."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re


class BuildError(ValueError):
    """An invalid graph, identity, path, or build result."""


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def relative_path(value):
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise BuildError("Expected a nonempty POSIX relative path")
    parts = value.split("/")
    if any(part in ("", ".", "..") for part in parts) or PurePosixPath(value).is_absolute():
        raise BuildError("Unsafe relative path: " + value)
    return value


def safe_path(root, relative):
    relative_path(relative)
    current = Path(root)
    for part in PurePosixPath(relative).parts:
        current = current / part
        if current.is_symlink():
            raise BuildError("Symlink path rejected: " + str(current))
    return current


def read_bytes(root, relative):
    path = safe_path(root, relative)
    if not path.is_file():
        raise BuildError("Missing regular file: " + relative)
    return path.read_bytes()


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise BuildError("Duplicate JSON key: " + key)
        result[key] = value
    return result


def read_json(root, relative):
    try:
        value = json.loads(read_bytes(root, relative), object_pairs_hook=_unique_pairs)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise BuildError("Invalid JSON: " + relative) from exc
    if not isinstance(value, dict) or type(value.get("schema_version")) is not int or value["schema_version"] != 1:
        raise BuildError("Expected an object with schema_version 1: " + relative)
    return value


def check_hash(value, expected, context):
    if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise BuildError("Invalid SHA-256: " + context)
    if digest(value) != expected:
        raise BuildError("Hash drift: " + context)


def _destination(output):
    # Reject symlinks in the complete output path before following any parent.
    destination = Path(os.path.abspath(str(output)))
    current = Path(destination.anchor)
    for component in destination.parts[1:]:
        current = current / component
        if current.is_symlink():
            raise BuildError("Symlink output ancestor rejected: " + str(current))
    if destination.exists():
        raise BuildError("Output already exists; choose a new directory: " + str(destination))
    return destination
