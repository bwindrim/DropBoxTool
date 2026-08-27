#!/usr/bin/env python3
"""List the top-level contents of a Dropbox account in read-only mode."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence

import dropbox
from dropbox.exceptions import AuthError, DropboxException
from dropbox.files import FolderMetadata


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="List top-level folders and files in Dropbox (read-only)."
    )
    parser.add_argument(
        "--access-token",
        default=os.getenv("DROPBOX_ACCESS_TOKEN"),
        help="Dropbox OAuth access token (or set DROPBOX_ACCESS_TOKEN).",
    )
    return parser.parse_args(argv)


def list_top_level(access_token: str) -> list[tuple[str, str]]:
    """Return (type, name) pairs for the account's root folder.

    The Dropbox SDK call used here is read-only: files_list_folder reads
    directory metadata and requires the app's files.metadata.read scope.
    """
    client = dropbox.Dropbox(oauth2_access_token=access_token)

    entries: list[tuple[str, str]] = []
    result = client.files_list_folder("")
    while True:
        entries.extend(
            ("folder" if isinstance(entry, FolderMetadata) else "file", entry.name)
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

    for entry_type, name in sorted(entries, key=lambda item: (item[0] != "folder", item[1].casefold())):
        print(f"{entry_type}\t{name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
