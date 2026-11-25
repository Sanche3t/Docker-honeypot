import json, re
from datetime import datetime, timezone
from urllib.parse import parse_qs
from flask import Flask, request, make_response

app = Flask(__name__)
LOG = "/export/web/web.jsonl"

SQLI = re.compile(r"(union\s+select|or\s+1=1|'--|sleep\(|information_schema|benchmark\()", re.I)
XSS = re.compile(r"(<script|onerror=|javascript:|<img[^>]+src)", re.I)
TRAV = re.compile(r"(\.\./|%2e%2e|/etc/passwd)", re.I)
CMDI = re.compile(r"(;|\|\||&&|`)\s*(cat|wget|curl|id|whoami|ls)\b", re.I)

LOGIN_PATHS = {"admin", "login", "administrator", "wp-login.php", "phpmyadmin", "user/login"}

LOGIN_HTML = """<html><head><title>Admin Panel</title></head><body>
<h2>Administrator Login</h2>
<form method="POST"><input name="username" placeholder="Username"><br>
<input name="password" type="password" placeholder="Password"><br>
<button>Sign in</button></form></body></html>"""

def detect_tags(blob):
    tags = []
    if SQLI.search(blob): tags.append("sqli")
    if XSS.search(blob): tags.append("xss")
    if TRAV.search(blob): tags.append("traversal")
    if CMDI.search(blob): tags.append("cmdi")
    return tags

@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "HEAD", "PUT", "OPTIONS"])
@app.route("/<path:path>", methods=["GET", "POST", "HEAD", "PUT", "OPTIONS"])
def catch_all(path):
    body = request.get_data(as_text=True)[:2000]
    form = {k: v[0] for k, v in parse_qs(body).items()} if "urlencoded" in (request.content_type or "") else {}
    p = path.strip("/").lower()
    if p in LOGIN_PATHS:
        status = 200
        resp_body = "Invalid username or password" if request.method == "POST" else LOGIN_HTML
    elif p == "":
        status, resp_body = 200, "<html><body><h1>It works!</h1></body></html>"
    else:
        status, resp_body = 404, "<html><body><h1>Not Found</h1></body></html>"

    rec = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "src_ip": request.remote_addr,
        "method": request.method,
        "path": "/" + path,
        "query": request.query_string.decode(errors="ignore")[:500],
        "ua": request.headers.get("User-Agent", "")[:300],
        "form": form,
        "status": status,
        "tags": detect_tags(f"{request.full_path} {body}"),
    }
    with open(LOG, "a") as f:
        f.write(json.dumps(rec) + "\n")

    resp = make_response(resp_body, status)
    resp.headers["Server"] = "Apache/2.4.41 (Ubuntu)"
    return resp

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)