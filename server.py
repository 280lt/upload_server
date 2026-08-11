#!/usr/bin/env python3
"""Simple HTTP Server With Upload — hardened version.

Improvements over the original (bones7456 / UniIsland gist):
  * Filenames are sanitised before being joined onto the target path,
    closing a directory-traversal write vulnerability (e.g. a filename
    of "../../etc/cron.d/x" could previously write outside the served
    directory).
  * Upload size is capped (--max-upload-mb) instead of trusting
    Content-Length blindly.
  * ThreadingHTTPServer instead of HTTPServer, so one slow upload
    doesn't stall every other client.
  * Multipart parsing is a little more defensive (quoted boundaries,
    missing filename, malformed headers all handled without a 500).
  * Optional HTTP Basic Auth (--user/--password) since the original
    has no authentication at all — fine on a trusted LAN, not fine
    exposed more broadly.
  * logging instead of print(), CLI args for port/bind/directory,
    duplicate-filename handling (won't silently clobber existing files
    unless --overwrite is passed).

Still true of this tool regardless of the fixes below: it grants
arbitrary file write to anyone who can reach it and send a POST
(subject to auth, if enabled). Only run it on networks/interfaces you
trust, and prefer --user/--password or a reverse proxy with auth in
front of it for anything beyond localhost.
"""

from __future__ import annotations

import argparse
import base64
import html
import http.server
import logging
import mimetypes
import os
import posixpath
import re
import shutil
import socketserver
import urllib.parse
from io import BytesIO

__version__ = "0.2"
__all__ = ["SimpleHTTPRequestHandler", "ThreadingHTTPServer"]

log = logging.getLogger("upload_server")


def secure_filename(filename: str) -> str:
    """Strip any path components and dangerous characters from a
    client-supplied filename.

    This is the fix for the directory-traversal write bug: the
    original code used the client-supplied filename verbatim in
    os.path.join(), so "../../../etc/passwd" (or an absolute path,
    which os.path.join happily lets clobber the first argument) could
    write anywhere the process had permission to write.
    """
    # Only keep the final path component — drop any directory parts
    # the client tried to sneak in, on both / and \ separators.
    filename = filename.replace("\\", "/")
    filename = posixpath.basename(filename)

    # Strip control characters and anything that isn't a reasonably
    # safe filename character.
    filename = re.sub(r"[^A-Za-z0-9._ -]", "_", filename).strip()

    # Guard against empty names, hidden dotfiles that resolve to
    # nothing useful, and reserved names like "." / "..".
    filename = filename.lstrip(".") or "upload"
    return filename


def _human_size(num_bytes: float) -> str:
    """Format a byte count the way `ls -lh` roughly would."""
    for unit in ("B", "K", "M", "G", "T"):
        if num_bytes < 1024 or unit == "T":
            return f"{num_bytes:.0f}{unit}" if unit == "B" else f"{num_bytes:.1f}{unit}"
        num_bytes /= 1024
    return f"{num_bytes:.1f}T"


# Extension -> (short badge label, CSS category) used in the directory
# listing. Kept restrained/categorical rather than one colour per
# extension.
_EXT_CATEGORIES = {
    **{e: "code" for e in (
        "py", "js", "ts", "sh", "c", "h", "cpp", "rb", "go", "rs", "html",
        "css", "json", "yml", "yaml", "md", "php", "java", "sql",
    )},
    **{e: "archive" for e in ("zip", "tar", "gz", "tgz", "rar", "7z", "bz2", "xz")},
    **{e: "image" for e in ("png", "jpg", "jpeg", "gif", "webp", "svg", "bmp", "ico")},
    **{e: "doc" for e in ("pdf", "doc", "docx", "txt", "csv", "xlsx", "ppt", "pptx")},
    **{e: "media" for e in ("mp4", "mp3", "wav", "mov", "avi", "mkv", "flac", "ogg")},
}


def _badge_info(name: str, is_dir: bool) -> tuple[str, str]:
    """Return (label, css-category) for the coloured badge next to a
    directory entry."""
    if is_dir:
        return "DIR", "dir"
    ext = posixpath.splitext(name)[1].lstrip(".").lower()
    category = _EXT_CATEGORIES.get(ext, "other")
    label = (ext or "file")[:4].upper()
    return label, category


# Shared look for every generated page: dark, monospace, built around
# the fact this tool is launched from and used alongside a terminal.
_CSS = """
:root{
  --bg:#0b0d12; --surface:#12151c; --surface-2:#181c25; --border:#242938;
  --text:#dfe3ea; --muted:#7d8494; --accent:#ffb454; --accent-dim:#8a5a1f;
  --ok:#5fd4a0; --danger:#ff6b6b;
  --cat-dir:#ffb454; --cat-code:#b98cff; --cat-archive:#5fd4c0;
  --cat-image:#6bc7ff; --cat-doc:#e0c46b; --cat-media:#ff8fb3; --cat-other:#7d8494;
}
*{box-sizing:border-box;}
html,body{margin:0;padding:0;}
body{
  background:var(--bg); color:var(--text);
  font:14px/1.6 ui-monospace,"JetBrains Mono","Fira Code",Menlo,Consolas,monospace;
  padding:32px 20px 64px;
}
.wrap{max-width:860px;margin:0 auto;}
.prompt{
  color:var(--muted); font-size:13px; margin-bottom:6px;
  white-space:pre-wrap; word-break:break-all;
}
.prompt .user{color:var(--ok);}
.prompt .host{color:var(--accent);}
.prompt .path{color:var(--text);}
.prompt .cursor{
  display:inline-block; width:8px; height:14px; background:var(--accent);
  margin-left:2px; vertical-align:-2px; animation:blink 1.1s steps(1) infinite;
}
@media (prefers-reduced-motion: reduce){ .prompt .cursor{animation:none;opacity:.8;} }
@keyframes blink{0%,49%{opacity:1;}50%,100%{opacity:0;}}
h1{
  font-size:18px; margin:2px 0 20px; font-weight:600; letter-spacing:.02em;
  color:var(--text);
}
h1 .muted{color:var(--muted); font-weight:400;}

.dropzone{
  border:1px dashed var(--border); border-radius:10px; background:var(--surface);
  padding:22px 20px; margin-bottom:22px; transition:border-color .15s, background .15s;
}
.dropzone.drag{ border-color:var(--accent); background:var(--surface-2); }
.dropzone-row{display:flex; align-items:center; gap:14px; flex-wrap:wrap;}
.dropzone-text{color:var(--muted); flex:1 1 220px; min-width:0;}
.dropzone-text b{color:var(--text); font-weight:600;}
.filename{color:var(--accent); word-break:break-all;}

input[type=file]{ display:none; }
.btn{
  appearance:none; border:1px solid var(--accent-dim); background:var(--surface-2);
  color:var(--accent); font:inherit; font-weight:600; padding:9px 16px;
  border-radius:7px; cursor:pointer; transition:background .15s, border-color .15s;
}
.btn:hover{ background:#20150a; border-color:var(--accent); }
.btn:focus-visible, a:focus-visible, input:focus-visible{
  outline:2px solid var(--accent); outline-offset:2px;
}
.btn[disabled]{ opacity:.5; cursor:not-allowed; }
.btn.secondary{ color:var(--text); border-color:var(--border); background:transparent; }

.progress{
  height:6px; border-radius:3px; background:var(--surface-2); overflow:hidden;
  margin-top:14px; display:none;
}
.progress.active{ display:block; }
.progress > i{
  display:block; height:100%; width:0%; background:var(--accent);
  transition:width .1s linear;
}
.status-line{ margin-top:10px; font-size:13px; color:var(--muted); min-height:18px; }
.status-line.ok{ color:var(--ok); }
.status-line.err{ color:var(--danger); }

table{ width:100%; border-collapse:collapse; }
th{
  text-align:left; font-size:11px; text-transform:uppercase; letter-spacing:.06em;
  color:var(--muted); font-weight:600; padding:0 10px 8px; border-bottom:1px solid var(--border);
}
td{ padding:9px 10px; border-bottom:1px solid var(--border); vertical-align:middle; }
tr:last-child td{ border-bottom:none; }
tr.row:hover td{ background:var(--surface); }
td.size, th.size, td.mtime, th.mtime{ color:var(--muted); white-space:nowrap; width:1%; }
a.entry{ color:var(--text); text-decoration:none; }
a.entry:hover{ color:var(--accent); text-decoration:underline; }
.badge{
  display:inline-block; font-size:10px; font-weight:700; letter-spacing:.02em;
  padding:2px 6px; border-radius:4px; margin-right:9px; min-width:34px; text-align:center;
}
.badge.dir{ background:color-mix(in srgb, var(--cat-dir) 18%, transparent); color:var(--cat-dir); }
.badge.code{ background:color-mix(in srgb, var(--cat-code) 18%, transparent); color:var(--cat-code); }
.badge.archive{ background:color-mix(in srgb, var(--cat-archive) 18%, transparent); color:var(--cat-archive); }
.badge.image{ background:color-mix(in srgb, var(--cat-image) 18%, transparent); color:var(--cat-image); }
.badge.doc{ background:color-mix(in srgb, var(--cat-doc) 18%, transparent); color:var(--cat-doc); }
.badge.media{ background:color-mix(in srgb, var(--cat-media) 18%, transparent); color:var(--cat-media); }
.badge.other{ background:color-mix(in srgb, var(--cat-other) 18%, transparent); color:var(--cat-other); }

.empty{ color:var(--muted); padding:18px 10px; }
footer{ margin-top:28px; color:var(--muted); font-size:12px; }
footer a{ color:var(--muted); }

@media (max-width:560px){
  th.mtime, td.mtime{ display:none; }
  body{ padding:22px 14px 48px; }
}
"""

# Progressive enhancement: the plain <form> works with JS disabled.
# With JS, drag/drop + an XHR upload with a real progress bar takes over.
_JS = """
(function(){
  var form = document.getElementById('uploadForm');
  var input = document.getElementById('fileInput');
  var zone = document.getElementById('dropzone');
  var label = document.getElementById('fileLabel');
  var bar = document.getElementById('progressBar');
  var fill = document.getElementById('progressFill');
  var status = document.getElementById('statusLine');
  var submitBtn = document.getElementById('submitBtn');

  function setFile(file){
    if(!file) return;
    label.innerHTML = 'Selected: <span class="filename"></span>';
    label.querySelector('.filename').textContent = file.name + ' (' + fmt(file.size) + ')';
  }
  function fmt(n){
    var units=['B','K','M','G']; var i=0;
    while(n>=1024 && i<units.length-1){ n/=1024; i++; }
    return (i===0? n : n.toFixed(1)) + units[i];
  }

  input.addEventListener('change', function(){ setFile(input.files[0]); });

  ['dragenter','dragover'].forEach(function(evt){
    zone.addEventListener(evt, function(e){ e.preventDefault(); zone.classList.add('drag'); });
  });
  ['dragleave','drop'].forEach(function(evt){
    zone.addEventListener(evt, function(e){ e.preventDefault(); zone.classList.remove('drag'); });
  });
  zone.addEventListener('drop', function(e){
    var files = e.dataTransfer.files;
    if(files && files.length){ input.files = files; setFile(files[0]); }
  });

  form.addEventListener('submit', function(e){
    if(!input.files.length) return; // let native validation handle it
    e.preventDefault();
    var xhr = new XMLHttpRequest();
    var data = new FormData(form);
    submitBtn.disabled = true;
    bar.classList.add('active');
    status.textContent = 'Uploading…';
    status.className = 'status-line';

    xhr.upload.addEventListener('progress', function(evt){
      if(evt.lengthComputable){
        var pct = Math.round((evt.loaded/evt.total)*100);
        fill.style.width = pct + '%';
      }
    });
    xhr.addEventListener('load', function(){
      submitBtn.disabled = false;
      if(xhr.status >= 200 && xhr.status < 300){
        fill.style.width = '100%';
        status.textContent = 'Upload complete — reloading…';
        status.className = 'status-line ok';
        setTimeout(function(){ window.location.reload(); }, 500);
      } else {
        status.textContent = 'Upload failed (HTTP ' + xhr.status + '). See response for details.';
        status.className = 'status-line err';
      }
    });
    xhr.addEventListener('error', function(){
      submitBtn.disabled = false;
      status.textContent = 'Upload failed — connection error.';
      status.className = 'status-line err';
    });
    xhr.open('POST', form.action || window.location.pathname, true);
    xhr.send(data);
  });
})();
"""


def _render_page(title: str, heading_html: str, body_html: str, prompt_path: str) -> bytes:
    page = f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<style>{_CSS}</style>
</head><body>
<div class="wrap">
  <div class="prompt"><span class="user">user</span>@<span class="host">upload-server</span>:<span class="path">{html.escape(prompt_path)}</span>$<span class="cursor"></span></div>
  <h1>{heading_html}</h1>
  {body_html}
  <footer>SimpleHTTPWithUpload/{__version__} · served from this machine, no external requests made by this page</footer>
</div>
</body></html>"""
    return page.encode("utf-8")


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """HTTPServer that handles each request in its own thread."""

    daemon_threads = True


class SimpleHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler supporting GET/HEAD/POST (upload)."""

    server_version = "SimpleHTTPWithUpload/" + __version__

    # Overridable via CLI / class attributes set by main().
    max_upload_bytes: int = 200 * 1024 * 1024  # 200 MB default
    allow_overwrite: bool = False
    auth_header: str | None = None  # e.g. "Basic base64(user:pass)"

    # ---- auth -----------------------------------------------------

    def _check_auth(self) -> bool:
        if self.auth_header is None:
            return True
        supplied = self.headers.get("Authorization")
        if supplied != self.auth_header:
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="upload"')
            self.send_header("Content-Length", "0")
            self.end_headers()
            return False
        return True

    # ---- HTTP verbs -------------------------------------------------

    def do_GET(self):
        if not self._check_auth():
            return
        f = self.send_head()
        if f:
            try:
                self.copyfile(f, self.wfile)
            finally:
                f.close()

    def do_HEAD(self):
        if not self._check_auth():
            return
        f = self.send_head()
        if f:
            f.close()

    def do_POST(self):
        if not self._check_auth():
            return
        ok, info = self.deal_post_data()
        log.info("%s upload from %s: %s", "OK" if ok else "FAILED",
                  self.client_address[0], info)

        referer = self.headers.get("referer", "/")
        status_class = "ok" if ok else "err"
        status_word = "Success" if ok else "Failed"
        inner = f"""
        <div class="dropzone">
          <p class="status-line {status_class}" style="margin-top:0;">
            <strong>{status_word}:</strong> {html.escape(info)}
          </p>
          <a class="btn secondary" href="{html.escape(referer)}">&larr; Back</a>
        </div>
        """
        page_bytes = _render_page(
            "Upload result",
            "Upload result",
            inner,
            urllib.parse.unquote(self.path),
        )
        body = BytesIO(page_bytes)
        length = len(page_bytes)
        self.send_response(200 if ok else 400)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(length))
        self.end_headers()
        self.copyfile(body, self.wfile)

    # ---- upload handling -------------------------------------------

    def deal_post_data(self):
        content_type = self.headers.get("Content-Type", "")
        if "boundary=" not in content_type:
            return False, "Content-Type header doesn't contain boundary"

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return False, "Invalid Content-Length header"

        if content_length <= 0:
            return False, "Empty request body"
        if content_length > self.max_upload_bytes:
            # Drain the socket so the connection can be cleanly closed
            # instead of left desynced, then reject.
            self._discard_body(content_length)
            return False, (f"Upload too large ({content_length} bytes, "
                            f"limit {self.max_upload_bytes} bytes)")

        boundary = content_type.split("boundary=", 1)[1].strip().strip('"').encode()
        remaining = content_length

        line = self.rfile.readline()
        remaining -= len(line)
        if boundary not in line:
            self._discard_body(max(remaining, 0))
            return False, "Content NOT begin with boundary"

        header_block = b""
        while True:
            line = self.rfile.readline()
            remaining -= len(line)
            if line in (b"\r\n", b"\n", b""):
                break
            header_block += line

        match = re.search(
            rb'Content-Disposition.*name="file"; filename="([^"]*)"',
            header_block,
        )
        if not match or not match.group(1):
            self._discard_body(max(remaining, 0))
            return False, "Can't find a file name in the upload"

        raw_name = match.group(1).decode("utf-8", errors="replace")
        filename = secure_filename(raw_name)
        if not filename:
            self._discard_body(max(remaining, 0))
            return False, "Rejected: empty/unsafe filename after sanitisation"

        target_dir = self.translate_path(self.path)
        if not os.path.isdir(target_dir):
            self._discard_body(max(remaining, 0))
            return False, "Target directory does not exist"

        dest_path = os.path.join(target_dir, filename)
        # Belt-and-braces: confirm the resolved path is still inside
        # target_dir even after sanitisation.
        if os.path.commonpath([os.path.abspath(dest_path),
                                os.path.abspath(target_dir)]) != os.path.abspath(target_dir):
            self._discard_body(max(remaining, 0))
            return False, "Rejected: path escapes target directory"

        if os.path.exists(dest_path) and not self.allow_overwrite:
            dest_path = self._unique_path(dest_path)

        try:
            out = open(dest_path, "wb")
        except OSError as exc:
            self._discard_body(max(remaining, 0))
            return False, f"Can't create file to write: {exc}"

        try:
            preline = self.rfile.readline()
            remaining -= len(preline)
            while remaining >= 0:
                line = self.rfile.readline()
                remaining -= len(line)
                if boundary in line:
                    preline = preline[:-1]
                    if preline.endswith(b"\r"):
                        preline = preline[:-1]
                    out.write(preline)
                    return True, f"File '{os.path.basename(dest_path)}' upload success!"
                out.write(preline)
                preline = line
                if not line:
                    break
            return False, "Unexpected end of data"
        finally:
            out.close()

    def _discard_body(self, nbytes: int) -> None:
        """Read and drop up to nbytes from the socket to keep the
        connection in a sane state after rejecting a request."""
        remaining = nbytes
        chunk = 65536
        while remaining > 0:
            data = self.rfile.read(min(chunk, remaining))
            if not data:
                break
            remaining -= len(data)

    @staticmethod
    def _unique_path(path: str) -> str:
        base, ext = os.path.splitext(path)
        i = 1
        candidate = path
        while os.path.exists(candidate):
            candidate = f"{base}_{i}{ext}"
            i += 1
        return candidate

    # ---- static file serving (unchanged behaviour, tidied up) -------

    def send_head(self):
        path = self.translate_path(self.path)
        if os.path.isdir(path):
            if not self.path.endswith("/"):
                self.send_response(301)
                self.send_header("Location", self.path + "/")
                self.end_headers()
                return None
            for index in ("index.html", "index.htm"):
                index_path = os.path.join(path, index)
                if os.path.exists(index_path):
                    path = index_path
                    break
            else:
                return self.list_directory(path)

        ctype = self.guess_type(path)
        try:
            f = open(path, "rb")
        except OSError:
            self.send_error(404, "File not found")
            return None

        try:
            fs = os.fstat(f.fileno())
            self.send_response(200)
            self.send_header("Content-type", ctype)
            self.send_header("Content-Length", str(fs.st_size))
            self.send_header("Last-Modified", self.date_time_string(fs.st_mtime))
            self.end_headers()
            return f
        except Exception:
            f.close()
            raise

    def list_directory(self, path):
        try:
            entries = os.listdir(path)
        except OSError:
            self.send_error(404, "No permission to list directory")
            return None
        entries.sort(key=str.lower)

        display_path = urllib.parse.unquote(self.path)

        rows = []
        if self.path not in ("/", ""):
            rows.append(
                '<tr class="row"><td colspan="3">'
                '<span class="badge dir">DIR</span>'
                '<a class="entry" href="../">.. (parent directory)</a>'
                '</td></tr>'
            )
        for name in entries:
            full = os.path.join(path, name)
            is_dir = os.path.isdir(full)
            is_link = os.path.islink(full)
            display_name = name + ("/" if is_dir else "@" if is_link else "")
            link_name = name + ("/" if is_dir else "")
            badge_label, badge_cat = _badge_info(name, is_dir)

            try:
                st = os.stat(full)
                size = "—" if is_dir else _human_size(st.st_size)
                mtime = self.date_time_string(st.st_mtime)
            except OSError:
                size = "—"
                mtime = "—"

            rows.append(
                '<tr class="row">'
                f'<td><span class="badge {badge_cat}">{html.escape(badge_label)}</span>'
                f'<a class="entry" href="{urllib.parse.quote(link_name)}">{html.escape(display_name)}</a></td>'
                f'<td class="size">{html.escape(size)}</td>'
                f'<td class="mtime">{html.escape(mtime)}</td>'
                '</tr>'
            )

        if not rows:
            table_html = '<p class="empty">Nothing here yet.</p>'
        else:
            table_html = (
                '<table><thead><tr>'
                '<th>Name</th><th class="size">Size</th><th class="mtime">Modified</th>'
                '</tr></thead><tbody>' + "".join(rows) + '</tbody></table>'
            )

        inner = f"""
        <form id="uploadForm" enctype="multipart/form-data" method="post">
          <div class="dropzone" id="dropzone">
            <div class="dropzone-row">
              <label class="btn" for="fileInput">Choose file</label>
              <input id="fileInput" name="file" type="file" required>
              <span class="dropzone-text" id="fileLabel"><b>Drag a file here</b>, or choose one, to upload it into this directory.</span>
              <button class="btn" id="submitBtn" type="submit">Upload</button>
            </div>
            <div class="progress" id="progressBar"><i id="progressFill"></i></div>
            <div class="status-line" id="statusLine"></div>
          </div>
        </form>
        {table_html}
        <script>{_JS}</script>
        """

        page_bytes = _render_page(
            f"Index of {display_path}",
            f'Index of <span class="muted">{html.escape(display_path)}</span>',
            inner,
            display_path,
        )

        f = BytesIO(page_bytes)
        length = len(page_bytes)
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(length))
        self.end_headers()
        return f

    def translate_path(self, path):
        path = path.split("?", 1)[0]
        path = path.split("#", 1)[0]
        path = posixpath.normpath(urllib.parse.unquote(path))
        words = [w for w in path.split("/") if w]
        path = os.getcwd()
        for word in words:
            _, word = os.path.splitdrive(word)
            _, word = os.path.split(word)
            if word in (os.curdir, os.pardir):
                continue
            path = os.path.join(path, word)
        return path

    def copyfile(self, source, outputfile):
        shutil.copyfileobj(source, outputfile)

    def guess_type(self, path):
        base, ext = posixpath.splitext(path)
        ext = ext.lower()
        return self.extensions_map.get(ext, self.extensions_map[""])

    if not mimetypes.inited:
        mimetypes.init()
    extensions_map = mimetypes.types_map.copy()
    extensions_map.update({
        "": "application/octet-stream",
        ".py": "text/plain",
        ".c": "text/plain",
        ".h": "text/plain",
    })

    def log_message(self, fmt, *args):
        log.info("%s - %s", self.client_address[0], fmt % args)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="0.0.0.0", help="address to bind to (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8000, help="port to listen on (default: 8000)")
    parser.add_argument("--directory", default=".", help="directory to serve (default: cwd)")
    parser.add_argument("--max-upload-mb", type=int, default=200,
                         help="max accepted upload size in MB (default: 200)")
    parser.add_argument("--overwrite", action="store_true",
                         help="allow uploads to overwrite existing files (default: rename instead)")
    parser.add_argument("--user", help="username for HTTP Basic Auth (requires --password)")
    parser.add_argument("--password", help="password for HTTP Basic Auth (requires --user)")
    parser.add_argument("--create-directory", action="store_true",
                         help="create --directory if it doesn't already exist")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")

    if bool(args.user) != bool(args.password):
        parser.error("--user and --password must be given together")

    if not (1 <= args.port <= 65535):
        parser.error(f"--port must be between 1 and 65535, got {args.port}")

    if args.max_upload_mb <= 0:
        parser.error(f"--max-upload-mb must be positive, got {args.max_upload_mb}")

    # --- validate/prepare the target directory with a clear message ---
    target = args.directory
    if not os.path.exists(target):
        if args.create_directory:
            try:
                os.makedirs(target, exist_ok=True)
                log.info("Created directory %r", os.path.abspath(target))
            except OSError as exc:
                log.error("Could not create directory %r: %s", target, exc)
                raise SystemExit(1)
        else:
            log.error(
                "Directory %r does not exist (resolved from cwd %r). "
                "Create it first, pass a different --directory, or add "
                "--create-directory to have it made automatically.",
                target, os.getcwd(),
            )
            raise SystemExit(1)
    elif not os.path.isdir(target):
        log.error("--directory %r exists but is not a directory", target)
        raise SystemExit(1)

    try:
        os.chdir(target)
    except OSError as exc:
        log.error("Could not switch into directory %r: %s", target, exc)
        raise SystemExit(1)

    if not os.access(os.getcwd(), os.W_OK):
        log.warning("Directory %r does not appear to be writable by this "
                     "process — uploads will likely fail with a "
                     "permission error.", os.getcwd())

    SimpleHTTPRequestHandler.max_upload_bytes = args.max_upload_mb * 1024 * 1024
    SimpleHTTPRequestHandler.allow_overwrite = args.overwrite
    if args.user:
        token = base64.b64encode(f"{args.user}:{args.password}".encode()).decode()
        SimpleHTTPRequestHandler.auth_header = f"Basic {token}"
        log.info("Basic auth enabled for user %r", args.user)
    else:
        log.warning("No auth configured — anyone who can reach this port can "
                     "read and upload files. Use --user/--password if this "
                     "isn't strictly localhost/trusted LAN.")

    # --- start the server with clear messages for the common failure modes ---
    try:
        httpd = ThreadingHTTPServer((args.bind, args.port), SimpleHTTPRequestHandler)
    except OSError as exc:
        if exc.errno == 98 or "Address already in use" in str(exc):
            log.error("Port %d on %s is already in use. Pick a different "
                       "--port, or find and stop whatever's using it "
                       "(e.g. `lsof -i :%d` / `ss -tlnp | grep %d`).",
                       args.port, args.bind, args.port, args.port)
        elif exc.errno == 13 or "Permission denied" in str(exc):
            log.error("Permission denied binding to %s:%d. Ports below "
                       "1024 usually need root/CAP_NET_BIND_SERVICE — "
                       "either run with sudo or use a port >= 1024.",
                       args.bind, args.port)
        elif exc.errno == 99 or "Cannot assign requested address" in str(exc):
            log.error("Can't bind to address %r — it doesn't belong to "
                       "any interface on this machine. Try --bind 0.0.0.0 "
                       "or 127.0.0.1.", args.bind)
        else:
            log.error("Failed to start server on %s:%d: %s",
                       args.bind, args.port, exc)
        raise SystemExit(1)

    with httpd:
        log.info("Serving %s on http://%s:%d", os.getcwd(), args.bind, args.port)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            log.info("Shutting down")


if __name__ == "__main__":
    main()
