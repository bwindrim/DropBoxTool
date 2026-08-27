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

The program follows Dropbox pagination automatically, so all top-level entries
are listed even when the account has more than one page of results.
