# 데이터 갱신 절차

새 로그가 왔을 때, 또는 규칙·모델이 바뀌었을 때 무엇을 다시 실행해야 하는지 정리한 문서다.
2026-11-25에 `streamlit_app/build_db.py`, `streamlit_app/build_ml.py`, `ml/cluster.py`를 **읽어서** 작성했다.
이 문서의 명령을 전부 실행해 검증하지는 않았다. 검증하지 않은 부분은 "확인 필요"로 표시했다.

## 1. 먼저 알아둘 것

- **덮어쓰기 주의**: `build_db.py`는 출력 폴더(기본 `data/dashboard/`)의 `seoul.db`, `syd.db`를 지우고 새로 만들고,
  `--ml`을 쓰면 `ml_out/`, `ml_models/`도 먼저 지운다. 실행 전에 출력 폴더를 통째로 복사해 두거나 `--out`을 새 폴더로 준다.
- **원본은 읽기만 한다**: 서울 로그 폴더와 시드니 DB 사본은 수정하지 않는다.
- **군집 번호는 학습 실행마다 다르다**: `--ml`(= `fit`)을 다시 하면 번호와 군집 이름이 바뀐다. 이전 결과·메모의 군집 번호와 섞어 쓰지 않는다.
- **실행 환경**: `hdbscan`이 있는 `.venv`가 필요하다 (`pip install -r streamlit_app/requirements.txt -r ml/requirements.txt`).

## 2. 어떤 상황에 무엇을 실행하나

| 상황 | 실행 | 군집 번호 | 비고 |
|---|---|---|---|
| 처음 만들기 / 새 로그를 전부 반영하고 싶다 | `build_db.py ... --ml` | **바뀜** | 서울 로그 전체를 다시 읽고 ML도 처음부터 학습 |
| `rules.yaml`만 바뀌었다 (로그 그대로) | `build_db.py` (`--ml` 없이) | 유지 | 탐지 결과(`hits`)만 새 규칙으로 다시 계산. ML은 규칙과 무관 |
| 새 로그를 반영하되 기존 군집 번호는 유지하고 싶다 | 아래 4절 (수동) | 유지 | 기존 모델에 새 세션만 배정 (`ml/cluster.py assign`). **도구로 연결돼 있지 않다** |
| ML 파라미터·정규화를 바꿨다 | `build_ml.py` 또는 `--ml` | **바뀜** | `NORMALIZE_VERSION`이 바뀌면 `assign`은 거부하고 재학습을 요구한다 |

## 3. 표준 절차 (전체 재빌드)

```sh
# 저장소 루트, 가상환경 활성화 후
.venv/Scripts/python streamlit_app/build_db.py \
    --seoul-logs <서울 Cowrie 로그 폴더> \
    --syd-db <시드니 DB 사본> \
    --geo work/geo/dbip-country-ipv4.csv \
    --ml
```

1. `--seoul-logs`의 로그를 `ingest.py`로 새로 적재한다 (`seoul.db`).
2. `--syd-db`를 복사한다 (`syd.db`). 시드니 사본에는 원본 로그가 없어 인증 실패·파일 실패·수집 공백이 "미수집"이다.
3. 현재 `signatures/rules.yaml`로 탐지를 다시 계산한다 (`dashboard.db`의 `hits`). 규칙 파일의 해시와 커밋이 `meta`에 기록된다.
4. `--ml`이면 서울+시드니를 합쳐 `ml.db`를 만들고 `ml/cluster.py fit`을 실행한다.
5. 결과는 `dashboard.db`·`ml.db`를 임시 파일로 만든 뒤 교체한다. 중간에 실패해도 이 둘은 이전 파일이 남는다.
   단 `ml_out/`, `ml_models/`는 시작할 때 먼저 지워지므로 ML 단계가 실패하면 이전 결과가 사라진다.

### 확인 필요
- `--ml` 없이 새 로그로 `build_db.py`만 돌리면 `dashboard.db`는 새 로그, `ml.db`는 이전 로그 기준이 된다.
  대시보드가 이 불일치를 알려 주는지 확인하지 않았다. 새 로그를 넣을 때는 `--ml`도 함께 쓰는 것이 안전하다.
- 앱은 헤더에 규칙 커밋만 보여 주고, 현재 `rules.yaml`과 다른지는 경고하지 않는다. 규칙이 바뀌었으면 2절의 두 번째 줄을 실행한다.

## 4. 새 로그를 기존 군집 번호로 추가하는 방법 (수동, 2026-11-25 서울 홀드아웃에서 사용)

기존 모델에 새 세션만 배정한다. 재학습하지 않으므로 군집 번호가 유지된다. 도구로 묶여 있지 않아 단계가 많다.

1. 새 로그를 **새 DB**에 적재한다: `python ingest.py <새 로그 폴더> --db <새.db> --source seoul`
2. 기존 `ml.db`를 **복사**하고, 새 DB의 `sessions`·`commands`를 `INSERT OR IGNORE`로 합친다. (원본 `ml.db`에는 하지 않는다. 직접 하는 SQL이라 사본에서만 한다.)
3. 사본에 대해 실행한다: `python ml/cluster.py assign --db <ml 사본> --out <출력 폴더> --models <기존 ml_models>`
   - `ml_clusters`에 없는 세션만 배정하고, 기존 세션의 배정은 바꾸지 않는다.
   - `--db`로 준 DB를 **수정**한다. 반드시 사본으로 실행한다.
4. 규칙 탐지(`hits`)는 새 세션 기준으로 별도 계산해야 한다 (`build_db.py`는 전체를 다시 계산한다).

한계: 모델이 처음 학습한 데이터 분포 밖의 새 행동은 가장 가까운 군집이나 노이즈(-1)로 배정된다.
시간이 지나면 정기적인 재학습이 필요할 수 있으며, 그 시점의 판단은 ML 담당 팀원과 정한다.

## 5. 서버 도입 후 자동화할 때 필요한 것 (아직 안 함)

- 서울 로그 가져오기 자동화 (지금은 서버에서 직접 받는다).
- 시드니 로그 전달 방식 (지금은 팀원이 DB 사본을 전달하며 11/07까지만 있다).
- 위 4절을 하나의 명령으로 묶기, 규칙 변경 감지 경고, 결과 폴더 백업.
- 이들은 빌드 스크립트 수정이라 범위와 ML 담당과의 협의를 정한 뒤 진행한다.

## 6. 데이터 폴더를 지정해서 대시보드 실행

`start-streamlit.cmd`는 저장소 안의 `.venv`와 `data/dashboard/`가 있어야 한다. 데이터나 가상환경이 저장소 밖에 있으면
환경변수 `HONEYPOT_DASHBOARD_DATA`(또는 앱 옵션 `--data`)로 데이터 폴더를 지정한다 (`streamlit_app/common.py`).

```sh
# Git Bash 예시 (경로는 자기 PC에 맞게)
export HONEYPOT_DASHBOARD_DATA=D:/Honeypot/repo/data/dashboard
<hdbscan이 설치된 .venv>/Scripts/python -m streamlit run streamlit_app/app.py --server.port 8501
```

```powershell
# PowerShell 예시
$env:HONEYPOT_DASHBOARD_DATA = "D:\Honeypot\repo\data\dashboard"
& "<.venv 경로>\Scripts\python.exe" -m streamlit run streamlit_app\app.py --server.port 8501
```

- 지정한 폴더에 `dashboard.db`, `seoul.db`, `syd.db`(그리고 패턴 분석용 `ml.db`)가 있어야 한다.
- 헤더의 "규칙 <커밋>"이 현재 `signatures/rules.yaml`의 마지막 커밋과 다르면 데이터가 이전 규칙 기준이다. 2절의 두 번째 줄을 실행한다.
- 2026-11-25에 이 방식으로 실행해 5개 화면이 오류 없이 열리는 것을 확인했다 (자동 실행 기준. 레이아웃·지도는 눈으로 확인하지 않았다).
