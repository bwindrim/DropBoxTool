#!/usr/bin/env python3
"""List the top-level contents of a Dropbox account in read-only mode."""

from __future__ import annotations

import argparse
from datetime import datetime
from fnmatch import fnmatchcase
from glob import has_magic
import os
import sys
from typing import Any
from collections.abc import Sequence

import dropbox
from requests.exceptions import RequestException
import yaml
from dropbox.exceptions import AuthError, DropboxException
from dropbox.files import FolderMetadata


class QuotedString(str):
    """String marker used to force quoting for filenames in YAML."""


class QuotedSafeDumper(yaml.SafeDumper):
    """YAML dumper with support for explicitly quoted strings."""


def represent_quoted_string(
    dumper: yaml.SafeDumper, value: QuotedString
) -> yaml.nodes.ScalarNode:
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style='"')


QuotedSafeDumper.add_representer(QuotedString, represent_quoted_string)

COMMON_METADATA_FIELDS = (
    "id",
    "name",
    "path_lower",
    "path_display",
    "parent_shared_folder_id",
    "preview_url",
)
FILE_METADATA_FIELDS = (
    "client_modified",
    "server_modified",
    "rev",
    "size",
    "is_downloadable",
    "content_hash",
    "has_explicit_shared_members",
    "media_info",
    "symlink_info",
    "sharing_info",
    "export_info",
    "property_groups",
    "file_lock_info",
)
FOLDER_METADATA_FIELDS = (
    "shared_folder_id",
    "sharing_info",
    "property_groups",
)


def serialize_metadata(value: Any) -> Any:
    """Convert Dropbox SDK values into values supported by safe YAML output."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (list, tuple)):
        return [serialize_metadata(item) for item in value]
    if isinstance(value, dict):
        return {str(key): serialize_metadata(item) for key, item in value.items()}
    if hasattr(value, "to_map"):
        return serialize_metadata(value.to_map())
    return str(value)


def normalize_dropbox_path(path: str) -> str:
    """Make a user-supplied path valid for Dropbox metadata endpoints."""
    if path.startswith(("/", "id:", "rev:", "ns:")):
        return path
    return f"/{path}"


def positive_float(value: str) -> float:
    timeout = float(value)
    if timeout <= 0:
        raise ValueError("must be greater than zero")
    return timeout


def entry_metadata(entry: Any, entry_type: str) -> dict[str, Any]:
    fields = COMMON_METADATA_FIELDS + (
        FILE_METADATA_FIELDS if entry_type == "file" else FOLDER_METADATA_FIELDS
    )
    metadata = {}
    for field in fields:
        value = serialize_metadata(getattr(entry, field, None))
        if field in {"name", "path_lower", "path_display"} and value is not None:
            value = QuotedString(value)
        metadata[field] = value
    return metadata


def format_size(size: int, as_bytes: bool = False) -> str:
    """Format a byte count for display using IEC units unless requested raw."""
    if as_bytes:
        return str(size)
    if size < 1024:
        return f"{size} B"

    value = float(size)
    for unit in ("KiB", "MiB", "GiB", "TiB", "PiB"):
        value /= 1024
        if value < 1024 or unit == "PiB":
            return f"{value:.1f} {unit}"
    return f"{size} B"  # Unreachable, but keeps the function total.


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="List top-level folders and files in Dropbox (read-only)."
    )
    parser.add_argument(
        "--access-token",
        default=os.getenv("DROPBOX_ACCESS_TOKEN"),
        help="Dropbox OAuth access token (or set DROPBOX_ACCESS_TOKEN).",
    )
    parser.add_argument(
        "--show-size",
        action="store_true",
        help="Include file size in human-readable form (folders show '-').",
    )
    parser.add_argument(
        "--size-bytes",
        action="store_true",
        help="Print sizes as raw bytes instead of human-readable units.",
    )
    parser.add_argument(
        "--show-hash",
        action="store_true",
        help="Include Dropbox content hash (folders show '-').",
    )
    parser.add_argument(
        "--yaml",
        action="store_true",
        help="Output structured YAML metadata instead of tab-separated text.",
    )
    parser.add_argument(
        "--timeout",
        type=positive_float,
        default=30.0,
        metavar="SECONDS",
        help="Network timeout for each Dropbox request (default: 30).",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        metavar="PATH",
        help="Dropbox file or folder paths to query instead of listing the root.",
    )
    return parser.parse_args(argv)


def list_top_level(
    access_token: str,
    paths: Sequence[str] = (),
    timeout: float = 30.0,
) -> list[tuple[str, str, int | None, str | None, dict[str, Any]]]:
    """Return type, display fields, and complete metadata for requested entries.

    With no paths, files_list_folder reads root directory metadata. With paths,
    files_get_metadata reads metadata for each specified file or folder. Both
    calls are read-only and require the files.metadata.read scope.
    """
    client = dropbox.Dropbox(oauth2_access_token=access_token, timeout=timeout)

    entries: list[tuple[str, str, int | None, str | None, dict[str, Any]]] = []
    seen_entries: set[str] = set()

    def add_entry(entry: Any) -> None:
        entry_type = "folder" if isinstance(entry, FolderMetadata) else "file"
        entry_key = getattr(entry, "id", None) or getattr(entry, "path_display", None) or entry.name
        if entry_key in seen_entries:
            return
        seen_entries.add(entry_key)
        entries.append(
            (
                entry_type,
                entry.name,
                getattr(entry, "size", None),
                getattr(entry, "content_hash", None),
                entry_metadata(entry, entry_type),
            )
        )

    if paths:
        wildcard_paths = [path for path in paths if has_magic(path)]

        for path in paths:
            if not has_magic(path):
                add_entry(
                    client.files_get_metadata(
                        normalize_dropbox_path(path),
                        include_has_explicit_shared_members=True,
                    )
                )

        if wildcard_paths:
            for pattern in wildcard_paths:
                normalized_pattern = normalize_dropbox_path(pattern)
                parent_path, name_pattern = normalized_pattern.rsplit("/", 1)
                if has_magic(parent_path):
                    raise ValueError(
                        f"wildcards are supported only in the final path component: {pattern}"
                    )
                result = client.files_list_folder(
                    parent_path,
                    recursive=False,
                    include_has_explicit_shared_members=True,
                )
                while True:
                    for entry in result.entries:
                        if fnmatchcase(entry.name, name_pattern):
                            add_entry(entry)
                    if not result.has_more:
                        break
                    result = client.files_list_folder_continue(result.cursor)
        return entries

    result = client.files_list_folder("", include_has_explicit_shared_members=True)
    while True:
        for entry in result.entries:
            add_entry(entry)
        if not result.has_more:
            break
        result = client.files_list_folder_continue(result.cursor)
    return entries

def print_yaml(entries: list[tuple[str, str, int | None, str | None, dict[str, Any]]]) -> None:
    """Print structured YAML metadata for the given entries."""
    print(
        yaml.dump(
            [
                {"type": entry_type, **metadata, "name": QuotedString(name)}
                for entry_type, name, _size, _content_hash, metadata in entries
            ],
            Dumper=QuotedSafeDumper,
            sort_keys=False,
            default_flow_style=False,
        ),
        end="",
    )


def print_text(entries: list[tuple[str, str, int | None, str | None, dict[str, Any]]]) -> None:
    """Print tab-separated text for the given entries."""
    for entry_type, name, size, content_hash, _metadata in entries:
        columns = [entry_type, name]
        if args.show_size:
            columns.append(
                "-" if size is None else format_size(size, as_bytes=args.size_bytes)
            )
        if args.show_hash:
            columns.append("-" if content_hash is None else content_hash)
        print("\t".join(columns))


def main(argv: Sequence[str] | None = None) -> int:
    global args
    args = parse_args(argv)
    if not args.access_token:
        print(
            "Error: provide --access-token or set DROPBOX_ACCESS_TOKEN.",
            file=sys.stderr,
        )
        return 2

    try:
        entries = list_top_level(args.access_token, args.paths, args.timeout)
    except AuthError:
        print(
            "Error: Dropbox rejected the token. Check that it is valid and has "
            "the files.metadata.read scope.",
            file=sys.stderr,
        )
        return 1
    except DropboxException as exc:
        print(f"Error communicating with Dropbox: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except RequestException as exc:
        print(f"Network error communicating with Dropbox: {exc}", file=sys.stderr)
        return 1

    sorted_entries = sorted(entries, key=lambda item: (item[0] != "folder", item[1].casefold()))
    if args.yaml:
        print_yaml(sorted_entries)
    else:
        print_text(sorted_entries)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
