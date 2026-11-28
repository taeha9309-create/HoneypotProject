# 고도화 개발 결과와 최종 평가 준비

2026-11-28 · HoneypotProject · T8

T0~T5와 T7a~T7b의 개발 결과를 확보했다. T6은 고유 순서 62개의 예비 판정 시트를 준비했고 두 사람의 독립 판정은 대기 중이다. 최종 평가 기준 시점 F는 미확정이다. 아래 결과는 11월 25일까지의 보관 자료에 한정된다. 11월 18~25일 구간은 개발과 이전 규칙 검증에 이미 사용됐다.

## 개발 결과

| 작업 | 확인한 결과 | 저장소 내 보관 위치 |
|---|---|---|
| T0 훈련 전용 모델 | 학습 4,675세션, 이후 구간 배정 4,114세션. 사본 작업 전후 원본 해시 일치 | work/advancement/T0_20261128.md |
| T1 기준선과 분할 | 8,789세션, 규칙 29개, 커버리지 99.2%, 구체화율 83.9%. 분할·결정성 기록 확보 | work/advancement/T1/ |
| T2 묶음 비교 | 세 분할 × 세 조건 완료. 주 분할에서 미관측 고유 순서의 규칙 일치 배정은 정확 일치 0/36, 편집 거리 11/36, ML 9/36 | work/advancement/T2/ 및 T2_run.log |
| T3 후보 초안 | 세 비교군에서 X04·X06 초안 11개. 정규식, 근거 세션, IP 수, 활동일과 일치 범위 기록 | work/advancement/T3/candidates.json |
| T4 E1 | 규칙 9개, 비교군 4개, 세 분할 × 세 조건, 부트스트랩 1,000회 | work/advancement/T4/rule_removal.json |
| T5 E3 | X06 개발용 동결 및 X04 기존 동결본과 별도 검증 | work/advancement/T5/ |
| T6 E2 준비 | 고유 순서 62개, 각자 전용 21개와 공통 20개. 100개 목표까지 38개 부족. AI 예비 판정은 별도 | work/advancement/T6/ |
| T7a 후보 관리 | X06 미승인 내보내기 차단. 합성 자료에서 승인, 별도 버전 내보내기, 전후 비교 검증 | work/advancement/T7a/ |
| T7b 읽기 화면 | Streamlit 메뉴에서 X06 상태와 지표, 가린 관련 세션 20건 표시 | streamlit_app/views/candidate_review.py |

T1에서 시드니 훈련의 최대 IP 비중은 60.1%였다. T2 주 분할의 미관측 세션 1,393개 중 1,052개(75.5%)가 ML 노이즈로 배정됐다. 두 수치는 분모와 함께 보존한다.

### E1 주 분할 · 시드니 → 서울, 기본 조건

고유 순서 단위의 규칙별 매크로 평균이다. 각 지표의 분모가 정의된 규칙으로 평균을 구했다.

| 비교군 | 정밀도 | 재현율 | 미관측 순서 재현율 |
|---|---:|---:|---:|
| 시그니처만 | — | 0.0% | 0.0% |
| 정확 일치 | 100.0% | 26.9% | 0.0% |
| 편집 거리 | 100.0% | 38.7% | 26.2% |
| ML 군집 | 80.5% | 26.7% | 19.6% |

미관측 순서의 ML−편집 거리 차이는 −6.6%p(95% 구간 −19.2~+3.5%p)였다. IP 상한 1을 적용했을 때는 ML 29.9%, 편집 거리 26.2%였다. E1은 숨긴 규칙의 훈련 적중을 그룹별 다수결에 쓰고, 평가 적중을 채점에만 쓴 그룹 복원 실험이다. 현재 개발 결과로는 어느 방식의 일관된 우위를 결론 내리기 어렵다.

### E3 텔넷 개발 검증 · 11월 18~25일 UTC

| 후보 | 일치 / 전체 4,086세션 | B19만 적중한 136세션 중 세분화 | 신규 커버리지 |
|---|---:|---:|---:|
| X04 기존 동결본 | 204 (4.99%) | 62 (45.6%) | 0 |
| X06 환경 탐침 관측 | 20 (0.49%) | 20 (14.7%) | 0 |

X06 20건은 서울 IP 한 개에서 나왔고 X04와 13건이 겹쳤다. T7a 재평가에서 개발 텔넷 구체화율은 96.06%에서 96.55%로 변했다. 전체 커버리지는 99.39%였고, 기존 정의를 유지하는 추가 방식에서 기존 적중 손실은 0건이었다. X06은 검토 대기 중이다.

## 개발 결과 재현

저장소 루트에서 Windows PowerShell을 실행한다. 아래 데이터 경로는 보관 개발 자료다. 기존 결과를 보존하도록 새 출력 폴더를 쓴다. T1·T2의 독립 재생성은 첫 묶음 명령, T3 이후의 보관 결과 재현은 두 번째 묶음 명령을 사용한다.

```powershell
$python = 'D:\HoneyPot\repo\.venv\Scripts\python.exe'
$archive = 'D:/HoneyPot/repo/data/dashboard'
$original = 'work/advancement'
$out = Join-Path $original ('T8_replay_' + (Get-Date -Format 'yyyyMMdd_HHmmss'))
New-Item -ItemType Directory -Path $out -ErrorAction Stop | Out-Null
$env:PYTHONDONTWRITEBYTECODE = '1'
$env:PYTHONIOENCODING = 'utf-8'
$env:OPENBLAS_NUM_THREADS = '1'

& $python -B -m unittest discover tests
& $python -B -m ml.analysis.gap_baseline --data-dir $archive --out "$out/T1/baseline"
foreach ($split in 'time','syd_to_seoul','seoul_to_syd') {
    & $python -B -m ml.analysis.splits run --data-dir $archive --split $split --out "$out/T1/splits"
}
foreach ($split in 'time','syd_to_seoul') {
    & $python -B -m ml.analysis.splits determinism --data-dir $archive --split $split --out "$out/T1/det"
}
& $python -B -m ml.analysis.grouping run --data-dir $archive --out "$out/T2"
```

```powershell
# 보관된 T2 모델과 기존 동결본을 사용한다.
& $python -B -m ml.analysis.candidate_gen --run-dir "$original/T2/time/full/time" |
    Set-Content -Encoding ascii "$out/T3_candidates.json"
& $python -B -m ml.analysis.eval_rule_removal --t2-dir "$original/T2" --dashboard-db "$archive/dashboard.db" |
    Set-Content -Encoding ascii "$out/T4_rule_removal.json"
& $python -B -m ml.analysis.eval_candidates evaluate --manifest "$original/T5/X06_freeze.json" --data-dir $archive |
    Set-Content -Encoding ascii "$out/T5_development_validation.json"
& $python -B -m ml.analysis.label_sample --data-dir $archive --t3 "$original/T3/candidates.json" --out "$out/T6" --pilot
& $python -B -m ml.analysis.rules_version review --registry "$original/T7a/candidates.db" --candidate X06 --data-dir $archive --out "$out/X06_review.json"
```

사람 판정이 완료되면 `python -m ml.analysis.kappa --manifest <비공개 매핑> --a <완료한 A CSV> --b <완료한 B CSV>`로 공통 표본의 일치도와 혼동행렬을 계산한다. 비공개 매핑과 AI 예비 답안은 두 판정자에게 전달하지 않는다. Streamlit의 **후보 검토** 메뉴에는 T7a 보관 보고서가 표시된다.

## 최종 평가 기준 시점 F 준비

| 동결 항목 | 준비된 증거 | 확정할 내용 |
|---|---|---|
| 후보와 기준 규칙 | X04 기존 동결본, X06 개발용 동결본, 기준 규칙 29개 | X06의 현재 두 패턴을 최종 평가에 사용할지와 허용 일치 비율 상한 |
| 모델과 훈련 자료 | 개발 모델의 코드·정규화·라이브러리·입력 해시, 보관 모델 파일 | 팀원 개선판 사용 여부, 훈련 소스·기간·세션 목록 및 최종 모델 파일 해시 |
| 전처리 | 정규화 버전 3과 개발용 테스트 IP·제외 조건 | 최종 전처리 코드와 제외 목록 버전 |
| 임계값 | 개발용 편집 거리 선택 규칙, ML 파라미터, 부트스트랩 1,000회와 시드 42 | 최종 모델별 임계값, IP·노이즈 처리 및 민감도 조건 |
| 평가 프로토콜 | E1 복원, E2 독립 사람 판정, E3 후보 검증, 고유 순서 주 지표 | 표본 목표와 파일럿 처리, 판정표 버전 및 새 데이터 실행 경로 검증 |

ADR 0001의 지표 정의와 ADR 0002의 읽기 전용 분석 구조는 개발 평가에 적용했다. ADR 0003의 시트와 κ 계산기는 준비됐고, 실제 독립 판정과 100개 표본이 남아 있다. 세 ADR의 저장소 상태는 `proposed`다.

### F 확정 이후 실행 순서

1. 최종 선택을 `work/advancement/FREEZE_F_<날짜>.md`에 봉인한다. F의 UTC 시각, 다섯 항목의 버전·해시, 담당자와 모델을 기록한다.
2. F 이후 수집한 서울·시드니 데이터만 별도 위치에 받는다. 수집 구간, 출처, 수신 이력, 원본 해시를 확인하고 사전에 취득·검토하거나 개발에 사용한 자료와 중복되는 파일·세션을 제외한다.
3. 사본에서 UTC 기준 `start_ts ≥ F` 조건과 동결한 전처리·제외 조건을 적용한다. 허니팟별 표본 수와 제외 이유를 기록한다.
4. 동결한 훈련 모델을 사본에 불러와 신규 세션을 배정한다. 평가 세션은 학습과 임계값 선택에서 제외한다. 고정된 규칙과 후보로 E1·E3를, 사람의 독립 판정으로 E2를 계산한다.
5. 출처별 분모, 전체·미관측 결과와 신뢰구간, 노이즈, 규칙 중복, 사람 판정 일치도를 보고한다. 기간이나 표본이 부족하면 파일럿으로 표시하고 같은 동결본으로 추가 수집분을 평가한다.

현재 T4·T5 실행기는 보관 개발 자료의 날짜와 해시에 고정돼 있다. **최종 평가용 실행 경로는 위 조건을 반영해 따로 구현하고 합성 자료에서 검증해야 한다.** 이 작업과 동결을 마칠 때까지 예약 자료를 열지 않는다.

## T8 재검증 기록

- T1 기준선을 다시 계산해 전체·허니팟·프로토콜 단위의 집계와 입력·규칙 해시가 기존 기록과 일치함을 확인했다.
- T2 보관 결과 9개와 현재 보관 입력·모델 코드 해시를 대조했다. 이번에는 T0·T2 학습을 새로 실행하지 않았다.
- T3 후보 초안, T4 부트스트랩 구간, T5 개발 검증, T7a 검토 결과를 동일한 보관 자료로 다시 계산했다. 모두 기존 JSON과 일치했다. T6의 두 시트와 비공개 매핑은 바이트 단위로 일치했다.
- 개발 기록 목록에는 T2 모델 파일 12개와 학습 배정 세션 키 목록의 해시를 남겼다. 학습 배정을 받은 세션 키의 해시는 향후 최종 훈련 입력 목록을 대신하지 않는다.
- 전체 테스트 219개를 다시 실행해 통과했다. 최종 평가용 예약 자료에는 접근하지 않았다.
