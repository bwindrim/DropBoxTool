#!/usr/bin/env python3
"""List the top-level contents of a Dropbox account in read-only mode."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence

import dropbox
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
    return parser.parse_args(argv)


def list_top_level(access_token: str) -> list[tuple[str, str, int | None, str | None]]:
    """Return (type, name, size, content_hash) tuples for the root folder.

    The Dropbox SDK call used here is read-only: files_list_folder reads
    directory metadata and requires the app's files.metadata.read scope.
    """
    client = dropbox.Dropbox(oauth2_access_token=access_token)

    entries: list[tuple[str, str, int | None, str | None]] = []
    result = client.files_list_folder("")
    while True:
        entries.extend(
            (
                "folder" if isinstance(entry, FolderMetadata) else "file",
                entry.name,
                getattr(entry, "size", None),
                getattr(entry, "content_hash", None),
            )
            for entry in result.entries
        )
        if not result.has_more:
            break
        result = client.files_list_folder_continue(result.cursor)
    return entries


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if not args.access_token:
        print(
            "Error: provide --access-token or set DROPBOX_ACCESS_TOKEN.",
            file=sys.stderr,
        )
        return 2

    try:
        entries = list_top_level(args.access_token)
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

    sorted_entries = sorted(
        entries, key=lambda item: (item[0] != "folder", item[1].casefold())
    )
    if args.yaml:
        print(
            yaml.dump(
                [
                    {
                        "type": entry_type,
                        "name": QuotedString(name),
                        "size": size,
                        "content_hash": content_hash,
                    }
                    for entry_type, name, size, content_hash in sorted_entries
                ],
                Dumper=QuotedSafeDumper,
                sort_keys=False,
                default_flow_style=False,
            ),
            end="",
        )
        return 0

    for entry_type, name, size, content_hash in sorted_entries:
        columns = [entry_type, name]
        if args.show_size:
            columns.append(
                "-" if size is None else format_size(size, as_bytes=args.size_bytes)
            )
        if args.show_hash:
            columns.append("-" if content_hash is None else content_hash)
        print("\t".join(columns))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
