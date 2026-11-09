# 로컬 대시보드 MVP

기준 main: `c9934d542251c22d1b40bdea4d0625c19ddad766` (2026-11-08).
작업 브랜치: `feat/dashboard-mvp`. 기존 ingest, 규칙, 시그니처 및 ML 분석 코드는 변경하지 않았다.
Python 표준 라이브러리 HTTP 서버와 기존 PyYAML 의존성을 사용한다. 별도 프런트엔드 빌드는 없다.

## 실행

저장소 루트에서 Python 3.10 이상으로 실행한다 (Windows PowerShell 및 macOS/Linux 동일).

```sh
python -m pip install -r requirements.txt
python -m dashboard.app --db data/honeypot.db
```

브라우저에서 http://127.0.0.1:8000 을 연다. 중지는 Ctrl+C.
포트 변경: `--port 8001`. DB 경로는 절대 경로도 가능하며 기본 경로는 저장소의 `data/honeypot.db`다.
서버는 127.0.0.1에만 연결한다. 배포·인증·외부 공개는 구현하지 않았다.

## 실제 데이터 준비 (기존 도구)

DB, 원본 로그, ML 모델 및 결과 CSV는 main에 포함되지 않는다. 따라서 최초 실행은 데이터 없음이 정상이다.
다음은 사용자가 보유한 실제 로그 경로로 실행한다. 대시보드는 이 명령들을 자동 실행하지 않는다.

```sh
python ingest.py data/raw/seoul --db data/honeypot.db --source seoul
python match_signatures.py --db data/honeypot.db
```

시그니처 명령은 기존 도구의 동작대로 저장된 탐지 결과를 다시 만든다.
ML 결과가 필요할 때만 별도로 실행한다. 기존 DB에 실제 ML 결과가 있다면 재학습이 필요 없다.

```sh
python -m pip install -r ml/requirements.txt
python ml/cluster.py fit --db data/honeypot.db
```

ML fit은 기존 분석 로직대로 ml_clusters를 재생성한다. 대시보드 실행에는 ML 패키지가 필요 없다.
`ml/RESULTS.md`의 과거 수치나 임의 CSV를 현재 DB 결과로 대체하지 않는다.

## 기능 및 집계 범위

- Overview: 테스트 제외 세션 수, commands의 중복 제거 입력 수, 세션 시작일별 추이, 프로토콜별 세션 수와 비율(미상 포함).
- 전체 수집 이벤트: `SUM(ingested_files.n_events)`. 테스트 포함, 유효한 session/timestamp가 있는 파일별 이벤트 합. 중복 파일 입력이나 파일 간 중복을 제거한 고유 이벤트 수가 아니다. 날짜·세션 범위와 일치하는 수치로 해석하면 안 된다.
- 로그인 시도: **미구현/DB 미저장**. 성공 세션 플래그로 시도 횟수를 추정하지 않는다. 원본 이벤트 저장이 필요하며 기존 ingest는 변경하지 않았다.
- Sessions: 출처, IP 부분 검색, SSH/Telnet, 시작일 범위(양끝 포함), 명령어 유무 필터. 50개씩 페이지 이동. source + session_id 복합키로 상세 조회.
- 상세: 기본 세션 정보, 명령어 시간순 흐름, 저장된 시그니처, 재평가 근거, 실제 ML 배정 결과. 로그인 시도 내역과 실패 명령어·다운로드 전용 UI는 미구현. 저장된 비밀번호는 표시하지 않는다.
- Detection: rules.yaml 한국어 이름과 코드, 탐지 세션 수, n_hits 합, 규칙별 최근 최대 200개 세션에서 상세 근거로 이동.
- 탐지 근거: S01/S02는 기존 explain_session, 다른 단일 규칙은 기존 match로 일치 입력 행, 시퀀스는 기존 rule_paths를 재사용. 현재 규칙으로 읽기 시 재평가하며 저장 결과와 불일치하면 명시한다. 원본 입력만으로 실제 실행 성공·악성을 확정하지 않는다.
- ML Analysis: ml_clusters가 있을 때 프로토콜 + cluster_id별 목록, 멤버 최대 200개와 배정 정보, 세션 상세 연결. -1은 노이즈. 대표 행동 요약은 미구현. 학습을 자동 실행하거나 군집 이름·데이터를 만들지 않는다.
- DB 시각 원문/시작일을 사용한다. 시간대 변환, 원본 이벤트 추이, 실시간 스트리밍, 지도, 모델 재학습 UI는 미구현.

DB는 mode=ro 및 query_only로 열며 생성·마이그레이션·수정하지 않는다. SQL 필터는 매개변수로 전달한다.
공격자 명령어는 HTML 이스케이프된 텍스트로 표시하고 실행하거나 외부 URL로 열지 않는다.
대규모 DB 성능 최적화와 운영 배포는 다음 단계다. 일부 목록은 위에 명시한 표시 상한이 있다.

## 검증

```sh
python -m unittest discover -s tests -p "test_dashboard.py" -v
python -m unittest discover -s tests -v
```

대시보드 테스트는 임시 DB에 **검증용 데이터만** 사용한다. 서비스에 샘플 데이터는 주입하지 않는다.
빈 DB 미생성, 실제 ingest 스키마 호환, 출처가 다른 동일 세션 ID 분리, 필터와 SQL 주입 문자열,
HTML 이스케이프, 시그니처 근거, 프로토콜별 ML 군집 분리, 조회 전후 DB 해시 불변을 확인한다.
실제 로그를 연결한 뒤 Overview → Sessions 필터 → 세션 상세 → Detection → ML을 수동 확인한다.

이번 환경 검증: 추가 테스트 4개 통과, 네 페이지 HTTP 200 확인. 실제 DB/원본 로그가 없어 실데이터 브라우저 검증은 수행하지 않았다.
전체 테스트 실행에서는 ML 선택 의존성 `hdbscan` 미설치로 test_ml 모듈을 불러오지 못했다.
ML 전체 검증은 위 ML 의존성을 설치한 환경에서 실행해야 한다.
