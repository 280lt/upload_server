# upload_server

A single-file, dependency-free HTTP server for quickly sharing and receiving files over a LAN — browse a directory, drag-and-drop to upload, done. Built on Python's standard library only, so it runs anywhere Python 3.10+ does with no `pip install`.

Originally based on the classic [`SimpleHTTPServer` + upload gist](https://gist.github.com/UniIsland/3346170), rewritten with a security fix, improved error handling, and a cleaner UI.

<img width="941" height="396" alt="Screenshot 2026-08-11 at 18 44 25" src="https://github.com/user-attachments/assets/54139fa5-e3ce-41b5-8bf2-291a82a4bc15" />

**Repo:** https://github.com/280lt/upload_server

## Features

- 📁 Browse and download files from any directory, with sizes and modified times
- ⬆️ Drag-and-drop upload with a live progress bar (works without JS too, as a plain form)
- 🔒 Upload filenames are sanitised against directory-traversal writes
- 🧵 Multithreaded — one slow transfer doesn't block everyone else
- 📏 Configurable max upload size, with existing files never silently overwritten
- 🔑 Optional HTTP Basic Auth
- 🧯 Clear, actionable error messages (bad directory, port in use, permission denied, etc.)
- 🎨 Self-contained UI — no CDN calls, works fully offline

## Requirements

- Python 3.10 or later
- No third-party packages

## Quick start

```bash
# Clone and run
git clone https://github.com/280lt/upload_server.git
cd upload_server
python3 server.py
```

By default this serves the current directory on `http://0.0.0.0:8000`. Open that address in a browser to see the file listing and upload form.

### Serve a specific directory with auth

```bash
python3 server.py \
  --directory ./shared \
  --port 8000 \
  --user alice \
  --password 'change-me'
```

## CLI options

| Flag | Default | Description |
|---|---|---|
| `--bind` | `0.0.0.0` | Address to listen on |
| `--port` | `8000` | Port to listen on |
| `--directory` | `.` | Directory to serve and receive uploads into |
| `--create-directory` | off | Create `--directory` automatically if it doesn't exist |
| `--max-upload-mb` | `200` | Reject uploads larger than this |
| `--overwrite` | off | Allow uploads to overwrite existing files (default: auto-renamed instead) |
| `--user` / `--password` | none | Enable HTTP Basic Auth (both required together) |

Run `python3 server.py --help` for the full list.

## Security notes

This is a convenience tool for trusted networks (home LAN, an internal engagement, a lab), not a hardened file server:

- **No auth by default.** Anyone who can reach the port can read and upload files unless `--user`/`--password` is set. The server logs a warning on startup if auth is disabled.
- **No TLS.** Credentials and file contents are sent in plaintext. If you need this reachable beyond a trusted LAN, put it behind a reverse proxy (e.g. Caddy or nginx) terminating HTTPS.
- **Upload = write access.** Anyone who can authenticate (or anyone at all, if auth is off) can write files into the served directory, up to `--max-upload-mb`.

Uploaded filenames are sanitised to prevent writing outside the target directory (the original gist this is based on did not do this).

## How it works

- `GET` / `HEAD` — serves files and directory listings from `--directory`
- `POST` (multipart/form-data, field name `file`) — saves the uploaded file into the current directory path

No database, no config file, no state beyond the filesystem it's pointed at.

## License

[MIT](LICENSE) — or update this section to match whatever license you're publishing under.
