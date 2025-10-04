# test_xss_full.py (improved)
import requests
from urllib.parse import quote_plus
import time
import re
from bs4 import BeautifulSoup

BASE = "http://127.0.0.1:5000"

# 페이로드 정의
REFLECT_PAYLOAD = "<script>alert('reflected')</script>"
STORED_PAYLOAD  = "<script>alert('stored')</script>"

sess = requests.Session()

# 위험 패턴(텍스트로 남아있어도 문제로 간주할 패턴)
JS_PATTERNS = [
    re.compile(r"alert\s*\(", re.IGNORECASE),
    re.compile(r"confirm\s*\(", re.IGNORECASE),
    re.compile(r"prompt\s*\(", re.IGNORECASE),
    re.compile(r"document\.cookie", re.IGNORECASE),
    re.compile(r"location\.href", re.IGNORECASE),
    re.compile(r"window\.open", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
]

def contains_js_patterns(text):
    if not text:
        return False
    for p in JS_PATTERNS:
        if p.search(text):
            return True
    return False

def extract_comments_from_index(html):
    """
    index.html의 댓글 리스트(.list-unstyled li)를 파싱하여
    각 코멘트의 '메타'와 '본문' 텍스트 및 내부 스크립트 태그 존재 여부 반환.
    """
    soup = BeautifulSoup(html, "html.parser")
    results = []
    # 댓글 항목 선택자: .list-unstyled li (index.html 구조 기준)
    for li in soup.select(".list-unstyled li"):
        meta_el = li.select_one(".muted")
        meta_text = meta_el.get_text(strip=True) if meta_el else ""
        content_el = None
        # 댓글 본문은 li > .card 또는 li .card 등으로 표시됨
        content_el = li.select_one(".card")
        if not content_el:
            # fallback: li 내부의 마지막 div
            divs = li.find_all("div")
            content_el = divs[-1] if divs else None
        content_text = content_el.get_text(separator=" ", strip=True) if content_el else ""
        has_script_tag = bool(content_el.find("script")) if content_el else False
        results.append({
            "meta": meta_text,
            "content_text": content_text,
            "has_script_tag": has_script_tag,
            "raw_html": str(content_el) if content_el else ""
        })
    return results

def extract_search_result(html):
    """
    search 페이지의 검색어 표시 부분만 파싱
    """
    soup = BeautifulSoup(html, "html.parser")
    # '검색 결과' 카드 내부의 <p> 또는 섹션에서 검색어 텍스트 추출
    node = soup.select_one("section.card p")
    text = node.get_text(" ", strip=True) if node else ""
    # also find any script tags in whole document or in that section
    has_script_tag = bool(soup.find("script"))
    return text, has_script_tag

def test_reflected():
    print("=== Reflected XSS Test ===")
    encoded = quote_plus(REFLECT_PAYLOAD)
    url = f"{BASE}/search?q={encoded}"
    r = sess.get(url)
    print("Request URL:", url)
    print("Status:", r.status_code)
    csp = r.headers.get('Content-Security-Policy')
    print("CSP header:", csp if csp else "(없음)")
    body = r.text

    search_text, has_script_tag = extract_search_result(body)
    print("Search displayed text:", search_text)
    # 판정 로직
    if has_script_tag:
        # 문서 전체에 스크립트 태그가 있더라도, search 카드 내부에 직접 스크립트가 있는지 먼저 확인:
        # (extract_search_result는 문서 전체 스크립트 존재만 리턴하는 단순 구현이므로 아래에서 더 엄밀히 검사)
        soup = BeautifulSoup(body, "html.parser")
        card = soup.select_one("section.card")
        inner_has_script = bool(card.find("script")) if card else False
        if inner_has_script:
            print("결과: 취약 - 검색 결과 카드 내부에 <script> 태그가 존재합니다.")
        else:
            # 외부(bootstrap 등) 스크립트는 문제 아님
            print("결과: 안전 - 문서에 script 태그가 있으나 검색 카드 내부에는 없음 (외부 스크립트 가능성).")
    elif "<script" in body:
        # fallback (대소문자 등)
        print("결과: 의심 - 문서에 '<script' 문자열이 존재합니다. 수동확인 권장.")
    elif contains_js_patterns(search_text):
        print("결과: 의심 - 검색어 텍스트에 JS 패턴(예: alert())이 포함되어 있음(이스케이프된 텍스트). 실행 불가 가능성 높음.")
    else:
        print("결과: 안전 - 검색어는 이스케이프되었거나 제거되었습니다.")
    print()

def test_stored():
    print("=== Stored XSS Test ===")
    # 1) POST로 댓글 등록 (테스트용 짧한 이름 사용)
    post_url = f"{BASE}/comment"
    data = {"name": "test-attacker", "content": STORED_PAYLOAD}
    r_post = sess.post(post_url, data=data, allow_redirects=False)
    print("POST", post_url, "->", r_post.status_code)
    # 서버가 리다이렉트하면 잠시 대기하고 루트 페이지 호출
    time.sleep(0.5)
    r_index = sess.get(f"{BASE}/")
    print("GET / ->", r_index.status_code)
    body = r_index.text

    comments = extract_comments_from_index(body)
    if not comments:
        print("결과: 댓글 항목을 찾을 수 없음 (템플릿 구조가 다름). 페이지 수동확인 필요.")
        return

    # 검사: 최신 댓글(리스트의 첫 항목) 중심으로 판정
    latest = comments[0]
    print("Latest comment meta:", latest["meta"])
    print("Latest comment content_text preview:", latest["content_text"][:200])

    if latest["has_script_tag"]:
        print("결과: 취약 - 댓글 본문 내부에 <script> 태그가 존재합니다 (실행 가능).")
    elif contains_js_patterns(latest["content_text"]):
        print("결과: 의심 - 댓글 본문에 JS 호출 패턴이 존재합니다 (텍스트로 남음). 권장: DB 정화 필요.")
    else:
        print("결과: 안전 - 댓글은 이스케이프되었거나 정화되어 실행 가능성이 낮음.")
    print()

if __name__ == "__main__":
    print("Starting improved XSS tests against", BASE)
    test_reflected()
    test_stored()
    print("테스트 완료.")
