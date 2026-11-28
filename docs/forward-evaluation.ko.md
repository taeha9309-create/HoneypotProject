# 최종 동결 이후 X04·X06 평가

이 실행기는 새 텔넷 입력에서 X04·X06의 일치 범위, B19 단독 적중의 세분화, 신규 커버리지, 규칙 간 중복을 집계한다. 서울과 시드니를 각각 표시하고 세션·고유 순서·IP 단위 결과를 제공한다. E1의 군집 기반 복원과 E2의 독립 사람 판정은 별도 단계다.

## 실제 실행 전에 확정할 파일

- **최종 동결 JSON**에는 확정 후에만 `status: confirmed`를 기록한다. 필드는 `frozen_at_utc`(타임존 포함 시각), `candidate_manifest_sha256`(선택된 개발 후보 동결본의 파일 해시), `min_days`, `min_telnet_sessions`다. 승인자가 결정한 양의 정수 두 개를 파일럿 기준으로 기록한다. 이 JSON은 모델과 전처리 설정을 포함하는 전체 F 기록을 보완한다.
- **배치 수신 JSON**에는 `collection_start_utc`, `collection_end_exclusive_utc`, `received_at_utc`, `previously_accessed`, `sources`, `database_sha256`을 기록한다. `sources`는 `seoul`과 `syd` 중 실제 포함된 소스 목록이다. 데이터 취급자가 사전 열람 여부와 출처를 확인하고, 사전 열람이 없을 때 `previously_accessed: false`로 기록한다. 실행기는 해당 기록과 해시를 검증하며, 실제 수집 이력을 독립적으로 확인할 수 있는 원본 기록은 별도로 보존한다.
- 보관 개발 DB는 교집합 확인에 사용한다. 후보 동결본에 기록된 개발 `ml.db` 해시와 일치해야 한다. 평가용 DB는 수신 기록과 해시가 일치하는 별도 사본을 써야 한다.

## 실행

아래 경로는 예시다. 실제 실행은 F 확정과 평가 배치 수신 후에 한다.

```powershell
python -m ml.analysis.forward_eval --freeze <최종동결.json> --receipt <수신기록.json> --candidates <X06_후보동결.json> --development-db <보관개발_ml.db> --new-db <신규평가_ml.db> --out <새_결과.json>
```

`--baseline`과 `--x04`를 생략하면 프로젝트 기준 규칙과 X04 기존 동결본을 사용하며 후보 동결본과의 해시 일치를 검사한다. 실행기는 F보다 앞선 배치, 개발 DB의 재사용, 개발 DB와 동일한 출처·세션 ID, 미완결 세션, 시간 범위를 벗어난 명령, 제외된 세션을 평가에서 제거하거나 입력 오류로 처리한다. 동일한 정규화 입력이 새 세션에서 다시 관측될 수 있으므로, 명령 순서가 같다는 이유만으로 새 세션을 제외하지 않는다. 내용이 재수집 과정에서 새 세션 ID를 받은 경우는 수신·원본 이력에서 확인해야 한다.

두 DB는 읽기 전용으로 열고, 결과 보고서에는 개별 세션 ID·IP·명령 원문을 넣지 않는다. 기간이나 표본 수가 확정 기준보다 작으면 `pilot`, 평가할 세션이 없으면 `no_eligible_sessions`로 기록한다. 기존 출력 파일은 덮어쓰지 않는다.
