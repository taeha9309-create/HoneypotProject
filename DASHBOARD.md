# 로컬 대시보드 MVP

## Overview 개편 (2026-11-10)

Overview에만 어두운 운영 모니터 형태의 카드 그리드를 적용했다. Sessions·Detection·ML 화면과 기존 분석 로직은 유지한다.

- KST 날짜/출처 선택, 어제/최근 수집일 바로가기. 최초 화면은 데이터가 있는 최신 날짜다.
- 선택일 접속 세션, 고유 IP, 명령어 수, 로그인 시도 카드. 명령어 수는 **선택일에 시작한 세션의 전체 입력 수**다.
- 실제 세션 시작 시각 기반 지도 하루 재생: 30/60/120초, 일시정지, 시각 슬라이더, 전체 복원.
- 국가 원 선택으로 반복 IP 순위와 접속 기록을 해당 국가로 필터링. 위치 미상은 지도에서 제외하되 전체 기록/순위에 포함한다.
- 같은 날 2회 이상 접속한 IP TOP 10, 시간대별 세션 막대, 최근 세션 30개, SSH/Telnet/미상 도넛.
- 로그인 계정·비밀번호 TOP 8: 현재 DB에서는 마지막으로 저장된 **성공 세션 요약**만 집계한다. 전체 시도나 실패 횟수로 해석할 수 없다.
- 실시간 확인은 **현재 KST 날짜의 DB를 10초마다 재조회**한다. 이 버튼은 원본 로그를 수집하는 기능이 아니다.
  현재 연결된 데이터는 11월 7일까지의 사본이므로 오늘 접속은 0, 새 데이터 대기로 표시된다. 과거 기록을 현재 공격처럼 재생하지 않는다.

### 실제 로그인 시도 로그 연결

전달받은 handoff 폴더에는 DB/CSV/문서만 있고 원본 시드니 Cowrie JSON 로그가 없다.
DB에 전체 인증 이벤트가 없으므로 현재 전체 로그인 시도 카드는 데이터 없음으로 남긴다.
원본 로그를 받으면 기존 ingest를 변경하지 않고 대시보드 전용 인증 이벤트 사본을 만든다.

```powershell
python -m dashboard.import_auth "실제/시드니/로그/폴더" --source syd
```

현재 DB의 source/session_id, 원본 IP(있을 때), 세션 시간 범위와 일치하는 success/failed 이벤트만 넣는다.
제외 세션은 넣지 않고 같은 이벤트 재입력은 중복 제거한다. 원본 DB는 읽기 전용이며
별도 `data/overview_auth.db`에만 저장한다. 날짜 범위에 실제 인증 이벤트가 있을 때 카드와 그래프가
원본 로그 기준으로 전환된다. 로그 일부만 연결했다면 그 범위의 집계이므로 전체 시도라고 확정하지 않는다.

### 지도 데이터와 정확도

공격 IP는 외부 API로 전송하지 않는다. DB-IP Country Lite 범위를 로컬에서 대조하고 Natural Earth의
국가 대표점에 원을 놓는다. 국가 추정이며 서버/공격자의 실제 도시·물리 좌표가 아니다.
VPN/프록시나 GeoIP 오류가 있을 수 있다. 현재 IPv4만 오프라인 조회하며 IPv6/조회 실패/지도에 없는 국가는 위치 미상이다.
수집 서버의 좌표를 임의로 만들거나 지도에 가상 공격선을 그리지 않는다.

자료 출처 및 라이선스:

- [DB-IP Country Lite (CC BY 4.0)](https://github.com/sapics/ip-location-db/tree/main/dbip-country), `dashboard/assets/DBIP-LICENSE` 보존 및 화면 링크 표시.
- [Natural Earth (public domain)](https://github.com/nvkelso/natural-earth-vector), 110m 국가 경계 및 국가 대표점.

지도 경계는 `dashboard/assets/world.json`, 이 PC의 실제 IP 조회 결과는 Git에서 제외한
`data/overview_geo.json`이다. 새 IP는 조회 자료를 다시 준비하기 전까지 위치 미상으로 표시한다.

```powershell
curl.exe -L --fail https://raw.githubusercontent.com/sapics/ip-location-db/main/dbip-country/dbip-country-ipv4.csv -o work/geo/country.csv
curl.exe -L --fail https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/geojson/ne_110m_admin_0_countries.geojson -o work/geo/world.geojson
python -m dashboard.prepare_geo --countries work/geo/country.csv --world work/geo/world.geojson
```

검증: KST 자정 경계, 출처/제외 필터, 과거/실시간 분리, 명령어 범위, HTML/JSON 이스케이프,
실제 인증 이벤트 중복 제거 및 원본 DB 해시 불변. 브라우저에서 재생·일시정지·국가 선택·실시간 대기·작은 화면과 데스크톱 배치를 확인했다.

## 실제 군집 산점도

ML Analysis에 클릭 가능한 SVG 군집 산점도를 추가했다. 자바스크립트·외부 시각화 서비스는 사용하지 않는다.
동일 정규화 패턴은 원 하나로 묶고, 원 크기는 세션 수를 로그 비례로 표시한다.
색은 저장된 cluster_id이며 노이즈는 회색이다. 범례로 강조하고 원을 눌러 멤버 세션으로 이동한다.

좌표는 기존 `ml.cluster.normalize_session`과 `features`를 재사용해 프로토콜별로 계산한다.
고유 패턴을 동일 가중치로 TF-IDF/SVD-L2 특징화한 뒤 PCA로 2차원 투영한다.
실제 학습 모델의 저장 좌표를 복원한 것이 아니며 군집 결과를 재학습·수정하지 않는다.
군집 번호로 위치를 만들거나 임의로 점을 벌리지 않는다. 축·거리·겹침은 2차원 근사치다.

좌표 생성은 저장소 루트에서 다음과 같이 실행한다 (전용 .venv에 기존 ML 의존성 설치 필요).

```powershell
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt -r ml/requirements.txt
.venv/Scripts/python -m dashboard.project_clusters
python -m dashboard.app
```

생성 결과는 Git에서 제외한 `data/cluster_projection.json`이다. 웹 서버에는 ML 패키지가 필요 없다.
현재 전달받은 handoff DB를 `dashboard.local.json`으로 선택해 좌표를 생성했다.
검증 결과: 1,401세션 / 26패턴 묶음. 군집별 611·609·74·74·12·10세션, 노이즈 11세션.
매 조회 때 대상 세션·명령어·군집의 지문을 확인하고, 현재 DB와 다르면 그림을 숨기고 재생성을 안내한다.
DB를 바꾸거나 분석 결과/명령어가 변경되면 좌표 생성 명령을 다시 실행해야 한다.

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

### 이 PC의 실제 DB 연결

발견한 운영 DB: `D:/HoneyPot/HoneypotProject/data/honeypot.db`.
추가 보관 DB: `D:/HoneyPot/HoneypotProject/data/honeypot_20261107.db`.
이번에는 사용자가 지정한 `honeypot.db`를 연결했다. 두 DB를 합치거나 재분석하지 않는다.

Git에서 제외한 `dashboard.local.json`에 다음 설정을 저장했다.

```json
{"db":"D:/HoneyPot/HoneypotProject/data/honeypot.db"}
```

이 설정을 사용할 때는 기존 서버를 Ctrl+C로 종료한 뒤 **DB 옵션 없이** 실행한다.

```sh
python -m dashboard.app
```

또는 `start-dashboard.cmd`를 실행한다. 기존의 `--db data/honeypot.db` 옵션을 붙이면
로컬 설정 대신 그 파일을 조회하므로 주의한다. 우선순위는 --db > HONEYPOT_DB 환경변수 > 로컬 JSON > 기본 data/honeypot.db다.

실제 DB 조회 검증: 전체 세션 4,676개 / 테스트 제외 4,664개, 테스트 제외 명령어 11,573개,
파일별 이벤트 집계 합 41,795개, 저장된 signature_hits 325행.
데이터 출처는 `cowrie-logs`, 세션 시작 범위는 2026-10-27 ~ 2026-11-02다.
이 DB에는 ml_clusters가 없다. 최신 수집 서버와 실시간 동기화한 데이터로 해석하면 안 된다.
각 화면 및 탐지 세션 상세를 실제 DB로 생성하고 조회 전후 SHA-256 일치를 확인했다.

화면은 어두운 사이드 메뉴, 통계 카드, 세션 추이 막대 차트, 프로토콜 비율 막대,
세션 표 및 작은 화면용 레이아웃으로 개선했다. 외부 이미지·폰트·CDN에 데이터를 보내지 않는다.

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
