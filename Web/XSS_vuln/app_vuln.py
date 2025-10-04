# app_vuln.py (권장 통합 수정본)
import sqlite3
import datetime
from flask import Flask, g, render_template, request, redirect, url_for

DATABASE = 'comments.db'
app = Flask(__name__)
app.secret_key = 'devkey'  # 실습용

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

@app.route("/", methods=["GET"])
def index():
    q = request.args.get('q')
    cur = get_db().execute('SELECT id, name, content, created_at FROM comments ORDER BY id DESC LIMIT 100')
    comments = cur.fetchall()
    return render_template('index.html', comments=comments, q=q)

@app.route("/comment", methods=["POST"])
def post_comment():
    name = request.form.get('name') or '익명'
    content = request.form.get('content') or ''
    created_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    db = get_db()
    db.execute('INSERT INTO comments (name, content, created_at) VALUES (?, ?, ?)',
               (name, content, created_at))
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

# 취약한 reflected XSS 예시 (app_vuln.py에 추가)
@app.route('/search')
def search():
    q = request.args.get('q', '')
    # 취약: q를 템플릿에서 이스케이프 없이 그대로 삽입하거나 |safe로 출력하면 반사형 XSS 발생
    return render_template('search_vuln.html', q=q)


# 디버그 용: 서버가 어떤 라우트를 등록했는지 확인하려면 아래 프린트를 유지하세요.
def print_routes():
    print("=== Registered routes ===")
    for rule in sorted(app.url_map.iter_rules(), key=lambda r: str(r)):
        print(rule)

if __name__ == "__main__":
    init_db()
    print_routes()
    app.run(debug=True, host='0.0.0.0', port=5000)
