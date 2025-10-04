# sanitize_db_strict.py
import sqlite3
import bleach
import re

DATABASE = "comments.db"
ALLOWED_TAGS = []   # 모든 태그 제거
ALLOWED_ATTRS = {}

def neutralize_js_patterns(text: str) -> str:
    # alert/confirm/prompt 등 제거
    text = re.sub(r"(?i)alert\s*\([^)]*\)", "[removed]", text)
    text = re.sub(r"(?i)confirm\s*\([^)]*\)", "[removed]", text)
    text = re.sub(r"(?i)prompt\s*\([^)]*\)", "[removed]", text)
    # 위험한 객체/속성 제거
    text = re.sub(r"(?i)document\.cookie", "[removed]", text)
    text = re.sub(r"(?i)location\.href", "[removed]", text)
    text = re.sub(r"(?i)window\.open", "[removed]", text)
    text = re.sub(r"(?i)javascript\s*:", "[removed]", text)
    # 스크립트 태그 제거 (case-insensitive, dotall)
    text = re.sub(r"(?is)<\s*script.*?>.*?<\s*/\s*script\s*>", "", text)
    return text

def sanitize():
    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()
    cur.execute("SELECT id, content FROM comments")
    rows = cur.fetchall()
    updated = 0
    for rid, content in rows:
        orig = content or ""
        clean = bleach.clean(orig, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS, strip=True)
        clean = neutralize_js_patterns(clean)
        if clean != orig:
            cur.execute("UPDATE comments SET content = ? WHERE id = ?", (clean, rid))
            print(f"Sanitized id={rid}")
            updated += 1
    conn.commit()
    conn.close()
    print(f"Done. Updated {updated} rows.")

if __name__ == "__main__":
    sanitize()
