# upload_server

A single-file, dependency-free HTTP server for quickly sharing files over a LAN — browse and download from any directory, or drag-and-drop to upload into it. Built on Python's standard library only, so it runs anywhere Python 3.10+ does with no `pip install`.

Originally based on the classic [`SimpleHTTPServer` + upload gist](https://gist.github.com/UniIsland/3346170), rewritten with a security fix, improved error handling, and a cleaner UI.

<img width="886" height="410" alt="Screenshot 2026-08-12 at 12 06 49" src="https://github.com/user-attachments/assets/2416a804-e2b2-40f3-b96c-d2e0c14bf750" />

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
| `--max-upload-mb` | `200` | Reject uploads larger than this. Use `0` for no limit |
| `--overwrite` | off | Allow uploads to overwrite existing files (default: auto-renamed instead) |
| `--user` / `--password` | none | Enable HTTP Basic Auth (both required together) |

Run `python3 server.py --help` for the full list.

## Security notes

This is a convenience tool for trusted networks (home LAN, an internal engagement, a lab), not a hardened file server:

- **No auth by default.** Anyone who can reach the port can read and upload files unless `--user`/`--password` is set. The server logs a warning on startup if auth is disabled.
- **No TLS.** Credentials and file contents are sent in plaintext. If you need this reachable beyond a trusted LAN, put it behind a reverse proxy (e.g. Caddy or nginx) terminating HTTPS.
- **Upload = write access.** Anyone who can authenticate (or anyone at all, if auth is off) can write files into the served directory, up to `--max-upload-mb`.
- **Why there's a default size cap.** The server has no way to know how large an incoming upload will be other than trusting the client's declared `Content-Length` — so without a limit, a single request (malicious or just a large accidental transfer) could fill available disk space before you could react. 200MB is a conservative default that covers typical file sharing without getting in the way; raise it with `--max-upload-mb` for larger transfers, or set `--max-upload-mb 0` to disable the cap entirely (the server logs a warning on startup when you do, since it removes this protection).
- **Uploads are never executed by this server** — it only writes bytes to disk and serves them back over `GET`/`HEAD`. However, if the served directory is also reachable through something that *does* execute files (e.g. Apache/nginx with PHP-FPM pointed at the same folder, a cron job scanning the directory, another service watching it), an uploaded webshell or script becomes remote code execution the moment it's requested through *that* other service — not through this tool directly.
- **Even without another execution path, this is an unauthenticated file-drop by default.** Anyone who can reach the port can upload arbitrary content (webshells, reverse shells, malware) and anyone who can reach it can download it, making an exposed instance a convenient staging/distribution point regardless of whether anything on the host actually runs it.
- This dual-use nature is intentional and well known: this exact pattern (a throwaway HTTP server used to host and retrieve payloads) is a standard part of legitimate red-team/pentest workflows. The property that makes it risky if exposed carelessly is the same property that makes it useful in an authorized engagement — treat it accordingly, and never point it at a directory served by another interpreter unless that's the deliberate goal.

Uploaded filenames are sanitised to prevent writing outside the target directory (the original gist this is based on did not do this).

## How it works

- `GET` / `HEAD` — serves files and directory listings from `--directory`
- `POST` (multipart/form-data, field name `file`) — saves the uploaded file into the current directory path

No database, no config file, no state beyond the filesystem it's pointed at.

## License

[MIT](LICENSE)
