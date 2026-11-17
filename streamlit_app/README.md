# Streamlit 대시보드 (MVP)

기획: [docs/dashboard-plan-v2.ko.md](../docs/dashboard-plan-v2.ko.md). handoff 브랜치의 `dashboard/`(HTML 서버)와는 별개이며,
그쪽의 지도 자산(`dashboard/assets/world.json`)만 가져다 쓴다.

| 화면 | 내용 |
|---|---|
| Overview | **새로 나타난 것**(새 파일 해시·다운로드 서버·위험 IP·처음 관측된 행동, 접속량 변화)과 **보고서 내려받기**(Markdown), 데이터 상태, KPI(직전 기간 대비), 접속 추이(프로토콜/허니팟), 국가 지도(세션/IP, 하루 재생), IP 집중도, 우선 확인 행동, 주요 탐지 행동, 인증, 수집 파일, 반복 접속 IP, 최근 입력 명령, **허니팟 상태**(로그인 후 명령 없이 끊은 비율, 수집 공백) |
| 세션 조사 | 탭 3개. **세션**: 필터, 세션 목록, 한눈에 보기(요약 문장·공격 단계 칩), 시간순 흐름, 탐지 근거. **IP**: 목록(인증 시도·비밀번호 종류·첫 성공까지 시도 수, 무차별 대입 순 정렬), 일별 활동, 세션, 탐지 행동, 사용 계정. **수집 파일**: 해시별 목록, 관측 세션, 다운로드 실패 |
| 탐지 분석 | KPI, 진행 단계(세션별 가장 깊이 간 단계), 위험도 순 행동 목록(규칙·ATT&CK), 행동 상세(설명·일치 입력·세션), 추가 분석(S01·S02 흐름 대상 / 규칙 미해당 입력 / 캠페인) |
| 위협 정보 (IOC) | 우리 환경 점검 포인트, **차단 후보 IP**(이유: 내려받아 실행·위험 행동·다운로드 시도·무차별 대입·반복 접속), **다운로드 서버**(명령 URL·tftp/ftpget 대상), **파일 해시**, **공격 계정**(조합·비밀번호·아이디 순위, 금지 목록 TXT), **서울·시드니 공통 IP**. 모두 CSV 내려받기. 차단 목록용이라 이 페이지만 IP를 가리지 않음 |

## 1. 준비 (처음 한 번, 로그를 새로 가져올 때마다)

```sh
python -m venv .venv
.venv/Scripts/python -m pip install -r streamlit_app/requirements.txt

# 국가 조회 자료 (DB-IP Country Lite, CC BY 4.0). work/는 git에 올리지 않는다
curl -L --fail https://raw.githubusercontent.com/sapics/ip-location-db/main/dbip-country/dbip-country-ipv4.csv -o work/geo/dbip-country-ipv4.csv

.venv/Scripts/python streamlit_app/build_db.py \
    --seoul-logs D:/HoneyPot/cowrie-seoul-logs \
    --syd-db data/syd_20261109/honeypot.db \
    --geo work/geo/dbip-country-ipv4.csv
```

`data/dashboard/`에 `seoul.db`(원본 로그를 ingest.py로 새로 적재), `syd.db`(사본), `dashboard.db`(인증·파일 이벤트,
현재 규칙으로 다시 계산한 탐지, 국가, 시간별 이벤트 수, 출처 정보)가 생긴다. 원본 로그와 입력 DB는 읽기만 한다.
최신 로그를 받으면 `--seoul-logs` 폴더만 바꿔 다시 실행한다.

## 2. 실행

```sh
.venv/Scripts/python -m streamlit run streamlit_app/app.py
# 다른 위치의 자료: streamlit run streamlit_app/app.py -- --data <폴더>
```

## 3. 기준 (기획서 4·5절 요약)

- 시각은 KST, 기간은 시작일 00:00 이상 ~ 종료일 다음 날 00:00 미만. 세션=시작 시각, 명령·인증·파일=각자 발생 시각, 탐지=규칙 최초 일치 시각.
- 테스트 접속(`excluded=1`)은 읽지 않는다. 인증·파일 이벤트도 세션·시간·IP가 맞는 것만 쓴다(handoff `import_auth.py`와 같은 기준).
- 원본 로그가 없는 출처(시드니 사본)는 인증·다운로드 실패·수집 공백이 **미수집**으로 표시된다(0건과 구분).
- 우선 확인 세션 = S01·S02·B04·B05·B06·B07·B15 중 하나라도 일치한 고유 세션.
- 행동 설명은 화면용이다. 근거가 "규칙 일치"일 때만 탐지이고 "입력 기반 추정"은 탐지 건수에 들어가지 않는다.
- 목록에서는 IP를 `a.b.x.x`로 가리고 상세 화면에서만 전체를 보여 준다. 예외: 위협 정보(IOC) 페이지는 차단 목록으로 쓰도록 전체 IP를 보여 준다. URL은 `hxxp://`로 바꿔 링크로 만들지 않는다.
  공격자 문자열은 HTML로 해석하지 않는다(지도 SVG에는 자체 국가 자산과 숫자만 들어간다).
- 국가는 IP 기반 추정이다. 화면에 DB-IP 출처 링크를 표시한다.

## 4. 보류 (MVP 이후)

- `later/`: 이전 Streamlit 버전의 ML 군집 화면. 서울·시드니 통합 재학습 여부를 정한 뒤 다시 붙인다.
