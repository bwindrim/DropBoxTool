# Project: Dropbox Backup Integrity Auditor

## Objective

Develop a Python command-line utility to verify the completeness and integrity of a directory tree stored in Dropbox against an independent local backup.

The local backup was created before the files were uploaded to Dropbox and is considered the authoritative reference.

The application must detect missing, additional, renamed and modified files without downloading their contents from Dropbox.

The application must be strictly **read-only with respect to both the local backup and Dropbox**. It must never upload, download, modify, rename or delete user files.

## Environment and scale

- Python 3, preferably using standard-library modules wherever practical.
- Official Dropbox Python SDK for API access.
- SQLite for persistent catalogues and scan history.
- Approximately 1.4 TB of data and 100,000 files.
- Local backup may reside on an external disk or NAS.
- Support Linux and macOS initially.
- Operate entirely from the command line.

## Core functionality

### 1. Configuration

Support configuration of:

- Local root directory.
- Corresponding Dropbox root directory.
- SQLite database location.
- Dropbox authentication credentials.
- Logging verbosity.

Use OAuth with the minimum Dropbox API permissions required for metadata access. Do not embed credentials in source code or store access tokens in the catalogue.

The two directory roots must be independently configurable.

### 2. Local file catalogue

Recursively enumerate all files and directories under the configured local root.

For each file, record:

- Relative path.
- File size.
- Modification timestamp (nanosecond precision where available).
- Dropbox-compatible content hash.
- Timestamp of the last successful verification.

Calculate hashes using Dropbox's published content-hash algorithm:

1. Divide the file into 4 MiB blocks.
2. Calculate SHA-256 for each block.
3. Concatenate the binary block digests.
4. Calculate SHA-256 over the concatenation.

Use streaming reads so memory consumption is independent of file size.

An empty file must be hashed correctly.

Cache calculated hashes in SQLite. During incremental scans, reuse cached hashes when file size and modification timestamp are unchanged.

Provide a full-verification option that recalculates every hash regardless of cached metadata.

Record and report unreadable files, permission errors and files that change during hashing. Do not silently treat these as successful verifications.

### 3. Dropbox catalogue

Use the Dropbox API to recursively enumerate the configured remote directory.

Record:

- Relative path.
- Dropbox file ID.
- File size.
- `content_hash`.
- Dropbox modification timestamp.
- File/folder type.

Use `files/list_folder` and `files/list_folder/continue`, handling pagination correctly.

Retain the Dropbox cursor to support incremental updates on subsequent scans.

Handle file additions, modifications, deletions and renames. Preserve the distinction between a deleted path and a moved file where possible.

Handle API errors, rate limiting, expired authentication and network interruptions gracefully.

A partial or failed remote scan must not replace the last complete, trusted catalogue.

Provide a mechanism to discard the cursor and rebuild the remote catalogue from scratch.

### 4. Comparison

Compare the local and remote catalogues using paths relative to their configured roots.

Classify results as:

- **Identical:** same relative path and matching content hash.
- **Missing remotely:** local file has no corresponding Dropbox file.
- **Extra remotely:** Dropbox file has no corresponding local file.
- **Content mismatch:** same path but different content hash.
- **Possible rename/move:** identical content hash found at a different path.
- **Directory mismatch:** missing or additional directory.
- **Unverified:** files that could not be successfully scanned.

Report file-size mismatches separately or as additional diagnostic information.

Handle differences in filesystem case sensitivity, Unicode filename normalization and path separators carefully. Never silently merge distinct local paths.

Do not classify an incomplete scan as evidence of deletion.

### 5. Scan modes

Implement the following operations:

**Initial scan**
- Build complete local and remote catalogues.
- Calculate all local file hashes.
- Produce a comparison report.

**Quick audit**
- Rescan local filesystem metadata.
- Recalculate hashes only for files whose size or modification time changed.
- Apply Dropbox changes using the stored API cursor.
- Produce a comparison report.

**Full verification**
- Recalculate all local hashes.
- Perform a fresh complete Dropbox listing.
- Compare the resulting catalogues.

### 6. Persistence and resilience

Use SQLite to retain:

- Local file catalogue.
- Dropbox file catalogue.
- Scan history.
- Detected discrepancies.
- Dropbox incremental-listing cursor.
- Scan completion status.

Design scans to be restartable after interruption.

Commit local hashing progress periodically, rather than requiring a complete restart after interruption.

Use transactions so incomplete remote updates cannot corrupt or partially replace a trusted catalogue.

Retain historical records of removals and modifications so that discrepancies can be investigated later.

Do not automatically redefine the authoritative baseline when files disappear or change.

### 7. Reporting

Provide a concise terminal summary showing:

- Number of local and remote files.
- Total bytes represented.
- Number of identical files.
- Missing remote files.
- Extra remote files.
- Content mismatches.
- Possible renames.
- Unverified files.
- Scan duration.

Provide detailed discrepancy reports in CSV and optionally JSON.

Use meaningful exit codes:

- Success: trees match.
- Differences detected.
- Scan incomplete or operational error.

Reports should distinguish newly detected discrepancies from previously recorded ones.

### 8. Performance

The application must be suitable for approximately 100,000 files and 1.4 TB of data.

Requirements:

- Bounded memory usage.
- Streaming file hashing.
- Efficient SQLite indexing.
- Avoid unnecessary rehashing.
- Efficient Dropbox API pagination.
- Progress reporting for long-running scans.
- No unnecessary remote content transfers.

Parallel local hashing may be considered, but correctness and predictable disk I/O are more important than maximum throughput.

### 9. Security

- Request read-only Dropbox API permissions.
- Never perform write operations through the Dropbox API.
- Never modify local backup contents.
- Keep authentication secrets out of SQLite and logs.
- Handle symbolic links safely; do not follow links outside the configured local root by default.
- Protect against accidental scanning of the wrong directory tree.

### 10. Testing and documentation

Include automated tests covering:

- Dropbox content-hash calculation, including empty files and block boundaries.
- Identical trees.
- Missing and extra files.
- Content modifications.
- Renamed files.
- Case-sensitive filename collisions.
- Interrupted scans and recovery.
- Failed API calls and pagination.
- Incremental deletion events.
- Files changing while being hashed.

Use mocked Dropbox API responses so most tests can run without a Dropbox account.

Provide a README describing installation, Dropbox app registration, OAuth configuration, database initialization and typical usage.

## Development approach

Implement the project in manageable stages:

1. Project structure, configuration, database schema and local file catalogue.
2. Dropbox authentication and remote catalogue.
3. Full comparison and reporting.
4. Resumable scans and incremental updates.
5. Historical reporting, robustness improvements and comprehensive tests.

Begin by proposing the architecture, database schema, CLI commands and implementation plan.

Identify any important ambiguities or design tradeoffs before writing the main implementation.

Prefer simple, maintainable code over unnecessary abstractions or dependencies.

Do not implement synchronisation or automatic repair functionality.