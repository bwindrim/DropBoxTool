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
