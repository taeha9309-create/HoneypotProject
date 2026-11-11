# 대시보드 팀 인수인계

작성: 2026-11-11 · 작업 브랜치: `feat/dashboard-handoff-20261111`

**현재 대시보드는 재기획 중인 로컬 프로토타입이다.** 기존 수집·시그니처·ML 분석 로직은 수정하지 않았다.
서버 배포와 main 병합은 하지 않았다. 기능 요구사항은 [대시보드 기획서](docs/dashboard-plan-v1.ko.md),
구현별 상세 설명은 [DASHBOARD.md](DASHBOARD.md)를 참고한다. 아래 실행 안내를 우선 사용한다.

## 1. 받아서 실행

```sh
git fetch origin
git switch --track origin/feat/dashboard-handoff-20261111
python -m pip install -r requirements.txt
python -m dashboard.app --db /실제/경로/honeypot.db
```

이미 로컬 브랜치가 있으면 해당 브랜치로 이동한다. DB 경로는 본인 PC의 경로로 바꾼다.
Windows 예: `python -m dashboard.app --db "D:/HoneypotProject/data/honeypot.db"`.
브라우저에서 http://127.0.0.1:8000/overview 를 연다. 포트 변경은 `--port 8001`.
실행 창은 유지하고 종료할 때 Ctrl+C를 누른다. Windows에서는 `start-dashboard.cmd`도 사용할 수 있다.

선택적으로 Git에서 제외되는 `dashboard.local.json`을 저장소 루트에 만들면 DB 옵션 없이 실행할 수 있다.

```json
{"db":"D:/HoneypotProject/data/honeypot.db"}
```

우선순위는 `--db` > `HONEYPOT_DB` 환경변수 > 로컬 JSON > `data/honeypot.db`다.
DB 연결이 안 되면 먼저 실행 명령의 `--db`가 다른 설정을 덮어쓰는지 확인한다.

## 2. DB와 자료 전달

**실제 DB, 공격자 입력·IP가 포함된 결과 CSV, 로그, 좌표 캐시, PC별 설정은 GitHub에 올리지 않았다.**
DB는 팀에서 별도 전달받아야 한다. 빈 화면이라고 가상 데이터를 넣지 않는다.

현재 로컬에서 검증한 자료는 `honeypot_handoff_20261109` 패키지의 시드니 DB 사본이다.
패키지에는 `honeypot.db`, `session_clusters.csv`, `cluster_summary.csv`, `novel_candidates.csv`,
`DATA_HANDOFF.md`가 있다. 인증 원본 JSON 로그는 포함되어 있지 않다.

검증 당시: 테스트 제외 11,376세션, 명령어 24,867개, ML 배정 1,401세션,
Telnet 6개 군집과 노이즈 11세션. 수집 범위는 10월 28일~11월 7일 UTC이며 마지막 날은 부분 수집이다.
이 값은 사본 검증값이며 하드코딩한 화면 데이터가 아니다.

기존 `cowrie-logs` 출처 DB와 시드니 DB를 합치는 작업은 아직 하지 않았다.
기존 DB가 서울인지 확인한 뒤 중복·분석 버전을 검토해야 한다. 기획서 10절 참고.

## 3. 구현 위치

| 파일 | 역할 |
|---|---|
| `dashboard/app.py` | 로컬 서버, 페이지 라우팅, 기존 조회 화면 |
| `dashboard/overview.py` | KST 날짜·출처별 Overview 집계 |
| `dashboard/assets/overview.js` | 지도 재생, 국가 필터, 도넛·그래프, DB 재조회 |
| `dashboard/assets/overview.css` | Overview 전용 디자인 |
| `dashboard/style.css` | 공통 레이아웃·기존 페이지 스타일 |
| `dashboard/prepare_geo.py` | 로컬 GeoIP 조회 자료 생성 |
| `dashboard/import_auth.py` | 원본 인증 이벤트의 대시보드용 보조 DB 생성 |
| `dashboard/project_clusters.py` | 기존 명령어 특징을 재사용한 2차원 시각화 좌표 생성 |
| `dashboard/projection.py` | 군집 그림·패턴 선택·데이터 지문 확인 |

서버는 SQLite를 읽기 전용으로 열고 127.0.0.1에만 연결한다. 기존 `ingest.py`,
`match_signatures.py`, 규칙과 ML 학습 코드는 변경하지 않았다.

## 4. 지도 준비 (본인 DB 기준)

GeoIP는 국가 단위 추정이며 외부 API에 공격 IP를 보내지 않는다. 세계 지도 경계와 라이선스는 코드에 포함했다.
DB별 조회 캐시는 제외했으므로 다른 PC에서는 한 번 생성해야 한다. 생성 전에는 위치 미상으로 표시된다.
아래는 Windows PowerShell 기준이다.

```powershell
New-Item -ItemType Directory -Force work/geo | Out-Null
curl.exe -L --fail https://raw.githubusercontent.com/sapics/ip-location-db/main/dbip-country/dbip-country-ipv4.csv -o work/geo/country.csv
curl.exe -L --fail https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/geojson/ne_110m_admin_0_countries.geojson -o work/geo/world.geojson
python -m dashboard.prepare_geo --db "D:/실제/경로/honeypot.db" --countries work/geo/country.csv --world work/geo/world.geojson
```

국가 대표점은 실제 서버 좌표가 아니다. DB-IP 화면 출처 링크와 라이선스는 유지한다.
새 IP는 조회 캐시를 다시 준비하기 전까지 위치 미상이다. 현재 준비 도구는 IPv4 조회만 지원한다.

## 5. 군집 그림 준비

```powershell
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt -r ml/requirements.txt
.venv/Scripts/python -m dashboard.project_clusters --db "D:/실제/경로/honeypot.db"
```

Linux/macOS에서는 `.venv/Scripts/python` 대신 `.venv/bin/python`을 사용한다.
좌표는 `data/cluster_projection.json`에 저장한다. **군집을 재학습하거나 DB를 수정하지 않는다.**
웹 서버 실행에는 기본 requirements만 필요하고, 좌표 생성 때 ML 패키지가 필요하다.
그림의 데이터 지문이 DB와 다르면 그림을 숨긴다. DB/명령어/군집이 바뀌면 다시 생성한다.

## 6. 미완성 기능과 주의할 해석

- **로그인 전체 시도 수:** DB에 원본 인증 이벤트가 없어 데이터 없음. 성공 세션 요약과 마지막 계정·비밀번호만 차트로 보여준다.
- 원본 로그를 받으면 `python -m dashboard.import_auth "로그폴더" --source syd --db "DB경로"`로
  `data/overview_auth.db`를 만든다. 실제 일치하는 세션·시간·IP만 수용하며 원본 DB는 보존한다.
- **실시간 버튼:** 오늘 KST 기준 DB를 10초마다 조회한다. 센서 수집/파일 전송/DB 반영 파이프라인은 아직 연결하지 않았다.
  과거 사본에서는 0건과 새 데이터 대기를 표시한다. 실시간 운영이 완성됐다고 설명하면 안 된다.
- Overview의 명령어 수는 현재 ‘선택일에 시작한 세션의 전체 명령어’다.
  재기획에서는 이벤트 발생 시각 기준 집계로 바꾸는 방향을 제안했다.
- 기존 파일별 이벤트 집계 합을 날짜별 고유 원본 이벤트 수로 사용하지 않는다.
- 기존 세션 날짜 필터와 새 Overview의 KST 필터는 기준이 완전히 통일되지 않았다.
- 군집 좌표는 고유 정규화 패턴의 TF-IDF/SVD-L2 → PCA2 근사 투영이다.
  원 크기는 같은 패턴의 세션 규모다. 저장된 학습 결과의 군집 번호는 유지한다.
- 서로 다른 학습 실행의 같은 군집 번호를 같은 군집이라고 합치지 않는다.
- 초기 서버에는 운영 인증·외부 공개·자동 동기화 기능이 없다. 배포는 별도 범위다.

## 7. 검증과 다음 작업

기본 환경에서 대시보드 테스트:

```sh
python -m unittest discover -s tests -p "test_dashboard.py" -v
python -m unittest discover -s tests -p "test_overview.py" -v
python -m unittest discover -s tests -p "test_projection.py" -v
```

전체 검증은 ML 의존성이 설치된 환경에서 실행한다.

```powershell
.venv/Scripts/python -m unittest discover -s tests -v
```

마지막 전체 검증: 113개 통과 (2026-11-10). 브라우저에서 지도, 하루 재생·일시정지,
국가 선택, 실시간 대기, 작은 화면/데스크톱 배치를 확인했다.
Windows의 제한된 실행 환경에서는 로컬 HTTP 테스트나 임시 파일 이름 변경이 권한 오류를 낼 수 있다.
일반 로컬 터미널에서 확인하고 제품 오류와 실행 권한 문제를 구분한다.

다음 우선순위:

1. 기획서의 Overview 지표와 최종 배치를 팀에서 합의.
2. 시드니 원본 인증 로그 및 실제 수집 연결 확보.
3. 날짜·출처·IP 필터의 화면 간 전달과 시간 기준 통일.
4. 기존 DB 출처 확인 후 두 자료의 통합 조회 검토.

이 브랜치는 `c9934d5` main을 기준으로 개발했다. 원격 main이 이후 변경되었다면 변경 내용을 검토한 뒤
병합/리베이스한다. 인수인계를 위해 main이나 팀원 브랜치를 강제로 덮어쓰지 않는다.
