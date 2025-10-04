# app_patched.py
import sqlite3
import datetime
from flask import Flask, g, render_template, request, redirect, url_for, make_response
import bleach
from flask_talisman import Talisman

DATABASE = 'comments.db'
app = Flask(__name__)
app.secret_key = 'devkey-for-local'  # 실습용. 배포 시 안전한 값 사용.

# 쿠키/세션 보안 설정 (로컬 테스트: SECURE False -> 배포 시 True로 변경)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,  # 배포 환경에서 True로 설정 필요
    SESSION_COOKIE_SAMESITE='Lax'
)

# CSP 및 기타 보안 헤더 설정 (간단한 예). 배포 시 정책을 더 엄격히 조정하세요.
csp = {
    "default-src": ["'self'"],
    "script-src": ["'self'"],
    "style-src": ["'self'", "https://cdn.jsdelivr.net"],  # bootstrap CDN 허용
    "img-src": ["'self'", "data:"],
    "connect-src": ["'self'"],
}
Talisman(app, content_security_policy=csp)

# bleach 허용 목록 (지금은 모든 태그 제거)
ALLOWED_TAGS = []          # 허용할 태그를 추가하려면 여기에 태그 이름을 넣으세요.
ALLOWED_ATTRS = {}         # 허용할 속성(예: {'a': ['href', 'title']})

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE, check_same_thread=False)
        db.row_factory = sqlite3.Row
    return db

def init_db():
    db = sqlite3.connect(DATABASE)
    db.execute('''CREATE TABLE IF NOT EXISTS comments
                  (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, content TEXT, created_at TEXT)''')
    db.commit()
    db.close()

@app.teardown_appcontext
def close_db(e=None):
    db = getattr(g, '_database', None)
    if db:
        db.close()

# 간단한 입력 검증: 길이 제한 및 공백 제거
def sanitize_search_input(q: str, max_len: int = 200) -> str:
    if not q:
        return ''
    q = q.strip()
    if len(q) > max_len:
        q = q[:max_len]
    # 추가 검증(허용 문자셋 등)을 원하면 여기서 처리
    # 예: 정규표현식으로 특수문자 제한 등
    return q

# index: 출력은 자동 이스케이프(템플릿에서 |safe 사용 금지)
@app.route("/", methods=["GET"])
def index():
    q = request.args.get('q', '')
    cur = get_db().execute('SELECT id, name, content, created_at FROM comments ORDER BY id DESC LIMIT 100')
    comments = cur.fetchall()
    return render_template('index.html', comments=comments, q=q)

# 댓글 저장: 입력 정화(bleach) 적용
@app.route("/comment", methods=["POST"])
def post_comment():
    name = request.form.get('name') or '익명'
    content = request.form.get('content') or ''
    created_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 입력 정화: 모든 태그 제거 (strip=True)
    clean_content = bleach.clean(content, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS, strip=True)
    db = get_db()
    db.execute('INSERT INTO comments (name, content, created_at) VALUES (?, ?, ?)',
               (name, clean_content, created_at))
    db.commit()
    return redirect(url_for('index'))

@app.route("/admin")
def admin():
    cur = get_db().execute('SELECT id, name, content, created_at FROM comments ORDER BY id DESC LIMIT 200')
    rows = cur.fetchall()
    return render_template('admin.html', rows=rows)

@app.route('/xss-guide')
def xss_guide():
    return render_template('xss_guide.html')

# 안전한 검색(Reflected XSS 방지: 입력 검증 + bleach + 출력 이스케이프)
@app.route('/search')
def search():
    q = request.args.get('q', '')
    q = sanitize_search_input(q, max_len=200)
    safe_q = bleach.clean(q, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS, strip=True)
    return render_template('search_safe.html', q=safe_q)

# 디버그용 라우트 출력
def print_routes():
    print("=== Registered routes ===")
    for rule in sorted(app.url_map.iter_rules(), key=lambda r: str(r)):
        print(rule)

# 추가 응답 헤더(필요 시 더 확장)
@app.after_request
def set_additional_headers(response):
    # Talisman이 대부분을 처리하지만, 추가로 확실하게 설정
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-Frame-Options', 'DENY')
    response.headers.setdefault('Referrer-Policy', 'no-referrer-when-downgrade')
    return response

if __name__ == "__main__":
    init_db()
    print_routes()
    app.run(debug=True, host='0.0.0.0', port=5000)
