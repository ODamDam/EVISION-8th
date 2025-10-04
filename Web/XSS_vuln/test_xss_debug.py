# test_xss_debug.py
import requests
import sqlite3
from urllib.parse import quote_plus

BASE = "http://127.0.0.1:5000"

def fetch(path):
    r = requests.get(f"{BASE}{path}")
    return r

def print_context(body, token="<script", window=60, label="body"):
    idx = body.find(token)
    if idx == -1:
        print(f"[{label}] token '{token}' not found.")
        return False
    start = max(0, idx - window)
    end = min(len(body), idx + window)
    snippet = body[start:end].replace("\n", " ")
    print(f"[{label}] token '{token}' found at pos {idx}: ...{snippet}...")
    return True

def show_search():
    payload = "<script>alert('reflected')</script>"
    enc = quote_plus(payload)
    url = f"/search?q={enc}"
    r = fetch(url)
    print("=== /search response ===")
    print("Status:", r.status_code)
    print("CSP header:", r.headers.get('Content-Security-Policy'))
    body = r.text
    # save to file for manual inspection
    with open("debug_search_response.html", "w", encoding="utf-8") as f:
        f.write(body)
    print("Saved full response to debug_search_response.html")
    # look for both literal <script and escaped &lt;script
    found1 = print_context(body, "<script", 120, "/search body")
    found2 = print_context(body, "&lt;script", 120, "/search body (escaped)")
    # also look for alert text
    if "alert('reflected')" in body or "alert(&#39;reflected&#39;)" in body:
        print("Note: the alert text appears in the body (may be escaped).")

def show_index_and_db():
    r = fetch("/")
    print("=== / (index) response ===")
    print("Status:", r.status_code)
    with open("debug_index_response.html", "w", encoding="utf-8") as f:
        f.write(r.text)
    print("Saved full response to debug_index_response.html")
    body = r.text
    _ = print_context(body, "<script", 120, "/ body")
    _ = print_context(body, "&lt;script", 120, "/ body (escaped)")

    # show last 20 rows from sqlite DB (if exists)
    print("\n=== DB: last 20 comments (raw) ===")
    try:
        conn = sqlite3.connect("comments.db")
        cur = conn.cursor()
        cur.execute("SELECT id, name, content, created_at FROM comments ORDER BY id DESC LIMIT 20")
        rows = cur.fetchall()
        for r in rows:
            print("ID:", r[0], "NAME:", r[1], "AT:", r[3])
            print("CONTENT RAW:", r[2])
            print("---")
        conn.close()
    except Exception as e:
        print("DB read error:", e)

if __name__ == "__main__":
    show_search()
    print("\n")
    show_index_and_db()
    print("\nDiagnostic files: debug_search_response.html, debug_index_response.html")
