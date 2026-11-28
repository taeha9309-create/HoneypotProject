# [팀원 전달] `ml/cluster.py` 이상 점수로 신규 패턴 후보가 부풀려지는 문제

작성: 2026-11-28. 상태: **제안(Draft)**. 우리는 `ml/cluster.py`를 수정하지 않았다. 수정 여부와 방식은 협의 후 정한다.

## 요약
`novel_candidates.csv`의 `outlier` 판정이 "이상 점수가 사실상 0인 세션"까지 포함해서 후보 수가 크게 부풀려진다. 원인은 프로토콜 전체 점수 분포의 95분위수를 임계값으로 쓰는 방식이다. 같은 명령 순서를 반복하는 봇이 점수를 0 근처에 몰아 놓으면 95분위수가 0에 가까워지고, 점수가 0보다 조금이라도 크면 전부 outlier가 된다.

## 원인 (코드 위치)
- `ml/cluster.py`의 `OUTLIER_QUANTILE = 0.95`, `write_outputs()`의 신규 패턴 후보 절:
  ```python
  threshold[proto] = float(np.quantile(sc, OUTLIER_QUANTILE))
  ...
  if sc > 0 and sc >= threshold[proto]:
      reasons.append("outlier")
  ```
- 이상 점수(`centroid_distance`)는 "가장 가까운 군집 중심까지 코사인 거리"다. 같은 순서가 반복되면 거리가 0에 가깝다. 정확히 0은 소수(약 10%)이고 대부분은 1e-9~1e-6 정도의 **부동소수점 오차 값**이다. 그래서 `sc > 0` 조건이 "0 제외" 역할을 하지 못하고 오차 값이 통과한다. (코드 주석대로 GLOSH가 0/NaN이 되어 이 방식을 쓴 것이다.)
- 점수 분포가 0에 크게 몰려 있어서, 분위수 임계값이 "의미 있는 이상"이 아니라 "0이 아님"으로 바뀐다.

## 재현 방법 (읽기 전용)
대시보드 데이터 `ml.db`(HONEYPOT_DASHBOARD_DATA 경로)에서:
```python
import sqlite3, numpy as np
con = sqlite3.connect('file:<경로>/ml.db?mode=ro', uri=True)
for p in ('telnet', 'ssh'):
    sc = np.array([r[0] for r in con.execute(
        "select outlier_score from ml_clusters where protocol=?", (p,))])
    t = np.quantile(sc, 0.95)
    print(p, len(sc), '정확히 0', round((sc == 0).mean(), 3), '사실상 0(<=1e-9)', round((sc <= 1e-9).mean(), 3),
          'q95', round(float(t), 5),
          'outlier 판정', int(((sc > 0) & (sc >= t)).sum()), '점수>=0.05', int((sc >= 0.05).sum()))
```

## 현재 데이터(서울+시드니 합본, 11/25)에서의 결과
| 프로토콜 | 세션 | 사실상 0(≤1e-9) 비율 | 95분위수 | outlier 판정 | 점수 0.05 이상 |
|---|---:|---:|---:|---:|---:|
| telnet | 8,703 | 50.6% | 0.00002 | 761 | 122 |
| ssh | 86 | 0.0% | 0.989 | 12 | 54 |

텔넷은 점수가 사실상 0인 세션 약 640개가 outlier로 잡힌다(정확히 0인 세션은 10.2%, 1e-6 미만은 91%이고, 95분위수 0.00002는 오차 수준이다). SSH는 표본이 작고 분포가 달라 문제가 거의 없다.

## 분석 결과에 미치는 영향
- `novel_candidates.csv` 원본: 106종·785세션, 화면에서 `noise` 또는 점수 0.05 이상으로 걸러서 87종·146세션을 보여 주고 있다(`streamlit_app/patterns.py`의 `NOVEL_MIN_OUTLIER = 0.05`).
- 이 보정은 화면에만 있다. CSV를 직접 쓰는 다른 분석은 부풀려진 값을 그대로 본다.
- 연구 평가에서 "신규 후보 수"를 지표로 쓰면 크게 왜곡된다.

## 권장 수정 방향 (협의 필요)
1. **절대 하한 병행**: `sc >= max(threshold, MIN_ABS)` (예: 0.05). 가장 작은 변경이다. 최소한 `sc > 0`을 `sc > 1e-6` 같은 허용 오차로 바꾸는 것만으로도 오차 값 문제는 막을 수 있다.
2. **고유 순서 단위로 점수 계산 후 분위수**: 같은 순서의 세션을 하나로 세서 반복 봇이 분포를 지배하지 않게 한다.
3. **군집별 기준**: 군집 안에서 중심에서 벗어난 정도를 상대적으로 판단한다.
4. 하한 값(0.05)은 현재 분포를 보고 정한 것이라 근거가 약하다. 정하기 전에 점수 분포 히스토그램을 같이 보면 좋겠다.

## 변경 시 같이 확인할 것
- `NORMALIZE_VERSION`과 모델은 그대로이므로 재학습은 필요 없다. 출력 단계만 바뀐다.
- `tests/test_ml.py`에 점수가 0 근처에 몰린 분포 케이스를 추가하면 회귀를 막을 수 있다.
- 바꾸면 `novel_candidates.csv` 숫자가 달라지므로 화면의 `NOVEL_MIN_OUTLIER` 보정과 중복되는지 확인해야 한다.

## 같이 이야기하고 싶은 것
군집화 개선 전반(고유 순서가 133개뿐이라 군집이 "같은 순서 묶기"와 비슷하게 나오는 점)은 `docs/advancement-analysis.ko.md` 2절 참고.
