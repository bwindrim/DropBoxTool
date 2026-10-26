# Dropbox top-level lister

This command-line program connects to Dropbox with an OAuth access token and
prints the folders and files directly inside the account root. It only calls
the read operation `files/list_folder`, so it does not upload, modify, move,
or delete anything.

## Setup

1. Create or use a Dropbox app in the [Dropbox App Console](https://www.dropbox.com/developers/apps).
2. Give the app only the `files.metadata.read` permission.
3. Generate an OAuth access token for that app.
4. Install the dependency:

   ```sh
   python3 -m pip install -r requirements.txt
   ```

## Usage

Pass the token directly:

```sh
python3 dropbox_ls.py --access-token 'your-token'
```

Add optional file metadata with either or both flags. Sizes are human-readable
by default:

```sh
python3 dropbox_ls.py --show-size --show-hash
```

Use `--size-bytes` with `--show-size` to print raw byte counts:

```sh
python3 dropbox_ls.py --show-size --size-bytes
```

Use `--yaml` for structured metadata output:

```sh
python3 dropbox_ls.py --yaml
```

To query specific files or folders instead of listing the root, provide one or
more Dropbox paths after the options:

```sh
python3 dropbox_ls.py /Documents /Photos/photo.jpg --yaml
```

Each supplied path is queried with a read-only metadata request. Ordinary paths
may be written with or without a leading `/`; the program adds it when needed.
Dropbox identifiers using `id:`, `rev:`, or `ns:` are passed through unchanged.
Shell-style wildcards are supported within one folder level; quote wildcard
arguments so the local shell does not expand them first:

```sh
python3 dropbox_ls.py '/Videos/*.mp4' '/Reports/**' --yaml
```

Wildcard matches are found by listing only the pattern's immediate parent
folder with a read-only request, and duplicate matches are emitted only once.
Wildcards are supported only in the final path component; for example,
`/Reports/**` matches entries directly inside `/Reports`, but does not descend
into nested folders.
If no paths are supplied, the program lists the complete top-level contents as
before.

Each Dropbox request has a 30-second network timeout by default. Change it with
`--timeout`, for example `--timeout 10`.

This outputs a YAML list with commonly-used Dropbox metadata. Shared fields
include `id`, `name`, `path_lower`, `path_display`,
`parent_shared_folder_id`, and `preview_url`. File entries also include
timestamps, `rev`, `size`, `is_downloadable`, `content_hash`, sharing and
locking metadata, and other available file properties. Folder entries include
`shared_folder_id`, sharing metadata, and property groups. Timestamps are
serialized as ISO 8601 strings. Filenames are always quoted and escaped as
YAML strings, so whitespace and special characters are preserved. Metadata
that Dropbox does not provide is represented as `null`. The `--show-size`,
`--show-hash`, and `--size-bytes` flags apply to the default tab-separated
output.

Or keep the token out of shell history by using an environment variable:

```sh
export DROPBOX_ACCESS_TOKEN='your-token'
python3 dropbox_ls.py
```

Output is tab-separated and labels each entry as `folder` or `file`:

```text
folder\tDocuments
folder\tPhotos
file\tgetting-started.pdf
```

With `--show-size`, the third column is the file size in human-readable IEC
units (for example, `1.5 KiB`). With `--size-bytes`, it is printed as raw
bytes. With `--show-hash`, the next column is Dropbox's content hash. Folders
show `-` for these file-only fields.

The program follows Dropbox pagination automatically, so all top-level entries
are listed even when the account has more than one page of results.

# Dropbox Backup Integrity Auditor

`dropbox_audit.py` is a separate Python 3.9+ CLI for Linux and macOS. It reads
local files and Dropbox **metadata only**. It has no synchronization or repair
commands. Install dependencies using the setup command above.

Create a scoped Dropbox app in the [App Console](https://www.dropbox.com/developers/apps).
Choose Full Dropbox access if the existing backup is outside an app folder;
app-folder access restricts the visible namespace. Enable only
`files.metadata.read`. Complete Dropbox's OAuth authorization flow requesting
that scope and `token_access_type=offline` for a refresh token. Keep tokens out
of source, reports and SQLite. Supply either `DROPBOX_ACCESS_TOKEN`, or
`DROPBOX_REFRESH_TOKEN` with `DROPBOX_APP_KEY` (and `DROPBOX_APP_SECRET` for
confidential apps). This utility accepts already provisioned OAuth credentials;
it does not implement an interactive OAuth browser flow. See the official
[OAuth guide](https://developers.dropbox.com/oauth-guide).

```sh
export DROPBOX_ACCESS_TOKEN='your-token'
python3 dropbox_audit.py --db "$HOME/audit.sqlite" init \
  --local-root /Volumes/Backup/Documents --dropbox-root /Documents
python3 dropbox_audit.py --db "$HOME/audit.sqlite" -v initial --csv "$HOME/initial.csv"
python3 dropbox_audit.py --db "$HOME/audit.sqlite" quick --json "$HOME/quick.json"
python3 dropbox_audit.py --db "$HOME/audit.sqlite" full
python3 dropbox_audit.py --db "$HOME/audit.sqlite" quick --rebuild-remote
python3 dropbox_audit.py --db "$HOME/audit.sqlite" history
python3 dropbox_audit.py --db "$HOME/audit.sqlite" report --csv "$HOME/issues.csv"
python3 dropbox_audit.py --db "$HOME/audit.sqlite" report --scan 2
```

Use `/` for the Dropbox account root. Roots are independent and pinned at init;
a changed local device/inode fails closed to help detect an absent external disk.
Use a new database to select a different root. Store the database on a local disk
with reliable SQLite locking, outside the backup. Its WAL/SHM and lock files are
also outside the backup. Reports must also be outside the backup, and use
exclusive creation so existing reports cannot be overwritten. Only one process
may operate on a catalogue at a time.

Exit codes: **0** match, **1** discrepancies, **2** incomplete/operational error.
`report` returns the saved scan's result. Terminal output is a compact JSON
summary containing file counts, bytes, identical files, discrepancy counts and
duration. CSV and JSON reports contain category, path, candidate path, diagnostic
and `is_new` (relative to the preceding comparison). Missing/extra files remain
in those counts even when also flagged as possible renames; these are candidates,
not automatic pairings. At most 20 rename candidates are emitted per local file.
CSV contains raw filenames; import as text if opening untrusted names in a
spreadsheet. Verbose logging reports hashing progress and remote pages.

`initial` builds the baseline, `quick` reuses hashes for unchanged size and
nanosecond mtime, and `full` hashes everything and lists Dropbox afresh.
Quick mode can miss edits that preserve both metadata values; use full regularly.
Retry an interrupted initial or quick scan to reuse committed hashes (committed
every 100 entries and directory). Full always rehashes. Local enumeration restarts;
remote requests restart from the last trusted cursor. Retry failures or use
`--rebuild-remote` after cursor expiration. Network/rate-limit retries are bounded;
long backoff, invalid authentication and API failures produce exit 2 without
printing SDK request details. Fix credentials in the environment and retry.

SQLite stores `config` (roots, baseline/snapshot pointers and cursor, no tokens),
`scans` (completion/history), `entries` (per-scan local/remote metadata and errors),
`cache` (restartable hashes), `issues` (historical discrepancies), and
`remote_events` (removed, modified or moved paths linked by Dropbox ID).
Entries are indexed by exact path, content hash and a case-folded NFC key.
All snapshots and discrepancies are retained; disk usage grows with scan history.
Inspect `remote_events` with SQLite to investigate ID-confirmed moves. The first
successful local catalogue remains the baseline; removals or content/type changes
produce `local_baseline_changed`, even when Dropbox matches the current local tree.
No command silently resets that baseline.

A failed local scan suppresses comparison entirely, avoiding false extra/deletion
claims. Use `history`, then `report --scan ID` for unreadable-path diagnostics.
A remote snapshot and cursor commit together only after complete pagination.
Previously trusted remote state survives failures. Dropbox files without hashes
are unverified. Exact path spelling is required: case and Unicode normalization
variants are never silently merged; collisions are separate discrepancies.
Symlinks and special files are unverified and never followed. Directory descriptors
protect local traversal against substituted symlinks. Hashing checks inode, size,
mtime and ctime before/after reading. Concurrent changes after enumeration can
still occur: scans are observations, not atomic filesystem snapshots. For the
strongest audit, keep both trees quiescent or audit an externally mounted snapshot.
Read access can update filesystem access times; mount the backup read-only if
physical metadata immutability is required.

Hashing uses streaming 4 MiB blocks following Dropbox's
[content hash specification](https://www.dropbox.com/developers/reference/content-hash).
Remote pagination and change application follow the official
[list_folder rules](https://docs.dropboxapi.com/dropbox-api/api-reference/user-endpoints/files/list-folder).
Memory is bounded by a directory/page and SQLite cursors rather than total data
size; hashing is serial to keep disk I/O predictable. SQLite snapshots use disk
space proportional to entries times retained scans.

Run account-free tests with the SDK installed:

```sh
python3 -m unittest discover -s tests -v
```

Tests cover hash boundaries/empty files, mutation detection, cache reuse/full
rehashing, excluded links and permissions, comparison categories, collisions,
historical baseline changes, pagination, transactional API failure and recursive
deletions. Live OAuth and account-specific shared-folder permissions require a
real-account smoke test; no live Dropbox scan is run by the tests.
