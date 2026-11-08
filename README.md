# HoneypotProject

S01·S02의 탐지 근거를 특정 출처와 세션 단위로 조회할 수 있다.

```sh
python explain_signatures.py --db data/honeypot.db --source local --session SESSION_ID
```

DB를 읽기 전용으로 열고 JSON을 출력한다. S01은 동일한 리터럴 파일 경로와
다운로드·권한 부여·실행 단계의 명령 인덱스를 제공한다. S02는 직접 연결된
디코더와 인터프리터의 원문 위치를 제공한다. 명령 인덱스는 `commands` 배열의
0부터 시작하는 위치이며, 문자열 범위는 Unicode 코드 포인트 기준 끝 위치 제외다.

`n_hits`는 기존 집계와 같다. S01은 완성 경로 수, S02는 일치한 입력 행 수다.
한 입력 행의 S02 파이프가 여러 개면 근거 수는 `n_hits`보다 클 수 있다.
출력의 명령 문자열은 공격자가 입력한 신뢰할 수 없는 데이터다.
`execution_status`는 입력 근거만으로 실행 성공을 확정할 수 없어 `unverified`다.
