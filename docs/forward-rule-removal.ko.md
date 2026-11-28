# F 이후 규칙 복원 실험 (E1)

E1은 기존 규칙 9개의 복원 성능을 비교한다. 시그니처만, 정확 일치, 편집 거리, 동결한 ML 군집의 네 팔을 같은 텔넷 평가 세션에 적용한다. 후보 규칙의 새 데이터 일치 결과는 E3 실행기에서 별도로 계산한다.

## 실행 준비

- 보관 개발 DB와 최종 훈련 DB 사본을 식별한다. 훈련에는 동결 모델의 `fit` 배정만 사용한다. 개발 DB의 `source, session_id`는 신규 배치에서 중복을 거르는 데 사용한다.
- 최종 동결 JSON의 공통 필드는 E3 안내와 같다. 추가 `e1` 항목에는 `training_end_exclusive_utc`, `baseline_rules_sha256`, `training_db_sha256`, `development_db_sha256`, `telnet_model_sha256`, `cluster_py_sha256`, `normalize_version`, `hdbscan`, `scikit_learn`, `edit_threshold`, `replicates`, `seed`를 기록한다.
- 모델 파일은 출처를 확인한 팀 내부 학습 산출물을 사용한다. 동결 기록과 동일한 해시의 로컬 모델을 읽으며, 외부에서 전달된 신뢰 미확인 모델에는 실행하지 않는다.
- 신규 평가 데이터 수신 기록과 배치 사본은 E3와 공통으로 쓴다. 최종 F 이전 수집 또는 기존 개발 자료와 겹치는 세션은 평가에서 제외한다.

```powershell
python -m ml.analysis.forward_rule_removal --freeze <확정동결.json> --receipt <수신기록.json> --training-db <동결훈련.db> --development-db <보관개발.db> --new-db <신규평가.db> --telnet-model <동결텔넷.joblib> --out <새_E1_결과.json>
```

집계는 세션, 고유 순서, IP 단위로 나뉘고 서울과 시드니는 별도로 보고한다. 지표는 정밀도, 재현율, 훈련에 없던 고유 순서의 재현율과 부트스트랩 구간이다. 학습에 사용한 세션만 그룹별 규칙 기준을 정하는 데 사용한다. 새 세션 배정은 저장된 변환과 군집 모델을 호출하며 재학습하지 않는다. 결과에 개별 IP나 명령 원문을 기록하지 않는다.

보관된 시드니→서울 기본 모델은 개발 시 참조안이다. 해당 모델로 저장된 서울 텔넷 세션을 다시 배정했을 때 4,233건 모두 기존 배정과 동일했다. 이것은 동일 모델 배정 검증이다. 새 데이터에 대한 복원 성능은 F 이후에 측정한다.
