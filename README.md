아래는 **당신의 프로젝트 목적·구조·사용 절차에 완전히 맞춘 README.md 완성본**입니다.
실제 GitHub에 바로 올릴 수 있는 수준으로 정리했습니다.
(문서 구조·설명·명령어·보안 주의사항·아키텍처 포함)

원하면 그림/다이어그램 버전도 생성해 드릴 수 있습니다.

---

# README.md

# EVISION-8th – Malware Behavior Simulation & Mini Sandbox

Windows 환경에서 동작하는 **악성코드 행위(Malicious Behavior)** 를 안전하게 재현하고,
해당 동작을 **동적 분석(API Hooking + 로그 기반 분석)** 으로 기록/리포팅하는
학습용 미니 샌드박스 프로젝트입니다.

본 프로젝트는 실제 악성 행위를 하지 않으면서,
• 악성코드가 흔히 사용하는 API 호출
• 정보 수집/유출 흐름
• 지속성(Persistence) 확보
• Hook 기반 모니터링
을 **안전하게 재현**하는 데 목적이 있습니다.

---

## 📌 프로젝트 구성 (Directory Structure)

```
sandbox/
│
├─ simulator/              # 악성 행위 시뮬레이터 (C++)
│    ├─ malicious_sim.cpp
│    └─ malicious_sim.exe (빌드 산출물)
│
├─ agent/                  # 샘플 실행·수집 Agent + API Hook DLL
│    ├─ agent.py
│    └─ monitor/
│         ├─ monitor.cpp
│         └─ monitor.dll  (빌드 산출물)
│
├─ analyzer/               # 호스트 분석기 (Python)
│    ├─ analyzer.py
│    └─ report.html (자동 생성)
│
├─ testdata/               # 더미 파일 생성 위치
├─ results/                # 시뮬레이터/모니터 결과 저장 위치
└─ README.md
```

---

## 🎯 프로젝트 목표

### 1) 악성코드가 수행하는 대표적 행동을 **안전하게 모방**

* 파일 시스템 재귀 탐색
* 특정 확장자(.txt, .pdf, .docx) 정보 수집
* Base64 + HTTP POST 형태의 “정보 유출” 시뮬레이션
* Run Key 등록을 통한 지속성 확보

### 2) Guest VM에서 **API Hooking 기반 행위 모니터링**

* CreateFileW, RegSetValueExW 후킹
* 파일 I/O 및 레지스트리 변경 기록
* 추후 WinHttpSendRequestW / socket 계열 확장 가능

### 3) Host 측 **자동 분석 / IOC 추출 / 리포트 생성**

* simulator_log + api_log 분석
* IOC(Indicators of Compromise) 생성
* MITRE ATT&CK 매핑
* HTML 리포트 자동 생성

---

## 🔥 악성 행위 시뮬레이터 (simulator)

### 수행되는 동작

1. **파일 시스템 탐색**

   * `testdata/` 경로만 재귀 탐색
   * `.txt`, `.docx`, `.pdf` 파일만 수집
   * 파일 크기·경로를 simulator_log.txt에 기록

2. **정보 유출 시뮬레이션**

   * 수집된 경로 리스트를 Base64 인코딩
   * HTTP POST → `http://127.0.0.1:8080/upload`
   * User-Agent: `"Mozilla/5.0 (MalClient)"`

3. **자동 실행 등록**

   * `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
   * 값 이름 `"SandboxSim"`
   * 실제 시스템 변경이지만 안전한 자기 자신 등록

---

## 🧪 Guest VM Agent + Monitor

### Agent (agent.py)

샘플을 수신하고 실행하는 단순 HTTP 서버:

| Endpoint         | 내용                   |
| ---------------- | -------------------- |
| `/upload_sample` | sample.exe 수신        |
| `/run`           | 샘플 실행 (cwd 설정)       |
| `/collect`       | results 폴더 zip 생성·전송 |

### Monitor DLL (monitor.dll)

MinHook 기반 API Hooking

* CreateFileW → 파일 생성/읽기 감시
* RegSetValueExW → Run Key persistence 감시
* Hook 결과는 `results/api_log.txt`에 기록
* 필요 시 WinHTTP, socket, VirtualAllocEx 등 확장 가능

---

## 📈 분석기 (analyzer)

`python analyzer.py` 실행 시:

* api_log / simulator_log 읽기
* IOC 추출
* MITRE ATT&CK 매핑
* HTML 보고서 생성

결과물:

```
analyzer/report.html
```

보고서 내 포함 정보:

* 파일 I/O 및 레지스트리 동작
* 의심 행위 탐지
* 네트워크 시도 여부
* IOC 요약
* ATT&CK Technique 매핑

---

## ▶ 실행 절차 (End-to-End)

### 1) Guest VM에서 Agent 실행

```bash
cd agent
python agent.py
```

### 2) Host에서 시뮬레이터 업로드 & 실행

```bash
curl.exe -X POST --data-binary @simulator/malicious_sim.exe http://127.0.0.1:8000/upload_sample
curl.exe -X POST http://127.0.0.1:8000/run
curl.exe -X POST http://127.0.0.1:8000/collect -o result.zip
```

### 3) 결과 분석

```bash
cd analyzer
python analyzer.py
```

### 4) 리포트 확인

```
analyzer/report.html
```

---

## 🛡 안전성 및 제한사항

본 프로젝트는 **실제 악성 행위를 포함하지 않습니다.**
안전한 테스트를 위해 다음 제약을 둡니다.

* 파일 접근 범위 제한: `testdata/` 내부만 탐색
* HTTP 전송 목적지 제한: localhost(127.0.0.1)
* 자동 실행 등록 대상: 자기 자신만 (sandbox-safe)
* API Hooking은 VM 내 프로세스에만 적용
* 외부 네트워크 연결 불가

따라서 실제 시스템에 피해를 주지 않는 구조입니다.

---

## 🧩 향후 확장 계획 (Optional)

* WinHTTP / socket 네트워크 API 상세 후킹
* PCAP 자동 캡처 + 네트워크 분석
* DLL Injection / Process Hollowing 시뮬레이션
* YARA + 정적 분석 도구 통합
* 프로세스 트리 시각화
