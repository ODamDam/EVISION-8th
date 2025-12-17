# memtool (Forensic Memory Dump Analysis Tool)

Windows 11 환경에서 실행 중인 프로세스의 메모리를 **Minidump**로 저장하고,
덤프 파일에서 **ASCII/Unicode 문자열 추출**, **키워드 검색(오프셋/문맥)**,
그리고 **JSON/HTML 리포트 생성(의심 문자열 하이라이트)** 을 수행하는 과제용 도구입니다.

> 주의: 본 도구는 **자신이 소유한 프로세스** 또는 **관리자 권한으로 접근 가능한 프로세스**에 대해서만 정상 동작합니다.
> 권한이 부족한 프로세스는 OpenProcess/MiniDumpWriteDump 단계에서 실패할 수 있습니다.

---

## Features

- 프로세스 목록 조회 (`list`)
  - PID, 프로세스명, 메모리 사용량(RSS), 실행 경로 출력
- 특정 프로세스 메모리 덤프 (`dump`)
  - PID를 입력받아 Minidump 생성
  - 생성된 덤프 옆에 `*.meta.json` 사이드카 파일로 PID/프로세스명/경로 기록
- 문자열 추출 (`strings`)
  - ASCII 문자열 추출
  - 옵션으로 UTF-16LE 문자열도 추출(`--unicode`)
  - 최소 길이(`--minlen`) 지정 가능
- 키워드 검색 (`search`)
  - 기본 키워드 세트 또는 사용자 지정 키워드 검색
  - 오프셋 + 주변 문맥(프린터블 + hex) 출력
- 리포트 출력 (`report`)
  - JSON 또는 HTML 또는 둘 다 출력
  - 의심 문자열(키워드 포함, JWT/Base64/Hex-like, 과도하게 긴 문자열 등)을 하이라이트

---

## Environment

- Windows 11
- Python 3.10+ 권장

---

## Installation

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
