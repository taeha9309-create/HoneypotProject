---
status: proposed
---
# 시그니처와 군집의 결합은 독립 교차 분석 모듈로 구현하고 `ml/cluster.py`는 바꾸지 않는다

폐루프(간극 발견 → 후보 생성 → 검증 → 승격)를 `ml/analysis/` 아래 읽기 전용 모듈로 만든다. 군집 결과(`ml_clusters`)와 적중(`hits`)을 `(source, session_id)`로 조인해서 쓰고, ML 코드는 팀원 담당이라 수정하지 않는다. 팀원과 합의한 뒤에만 ML 쪽 변경(예: 이상 점수 보정)을 한다.

## Considered Options
- 규칙 적중을 ML 특징으로 넣기(하이브리드): 군집이 규칙을 되풀이하는 순환이 생기고 ML 핵심 변경이라 기각.
- ML을 직접 고쳐 신규 후보 판정 개선: 팀원 협의 전이라 보류.

## Consequences
- 이상 점수 문제는 화면에서만 보정된 상태로 남는다(`NOVEL_MIN_OUTLIER`).
