# 시퀀스 탐지 실행

```sh
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python ingest.py <로그 파일 또는 폴더> --db data/honeypot.db --source local
python match_signatures.py --db data/honeypot.db --examples S01
```

분석 서버 없이 Python과 SQLite로 실행한다. 테스트는 임시 로그/DB만 사용한다.

기존 `patterns` 규칙 18개는 그대로 유지한다. `sequence`에는 순서대로
일치해야 하는 정규식을 두 개 이상 적는다. 두 필드는 함께 사용할 수 없다.
`type`은 기존처럼 `behavior` 또는 `campaign`이다.

S01은 wget/curl 다운로드 → chmod 실행 권한 → ./파일 또는 sh/bash 스크립트
입력 순서를 검사한다. 세션 키는 ingest의 `(source, session_id)`를 사용하며,
중간에 관계없는 명령어가 있어도 허용한다. 한 입력 줄에서는 정규식의 문자 위치가
앞으로 진행해야 한다. 서로 다른 줄은 시간대가 있는 ISO 시각을 UTC로 비교하며,
동일 시각의 입력끼리는 순서를 추측하지 않는다. 유효하지 않거나 시간대가 없는
시각은 시퀀스 검사에서 제외한다. 기존 단일 규칙의 동작에는 영향을 주지 않는다.

`signature_hits` 스키마는 유지한다. 시퀀스의 `first_ts`는 첫 완성 경로의 시작
시각이고 `n_hits`는 겹치지 않는 완성 경로 수다. 한 입력 줄에서 완성은 최대
한 번만 센다. `--examples S01`은 완성 경로를 표시한다. 재실행하면 기존처럼
전체 탐지 결과를 다시 만든다.

제한: 셸 구문을 실행하거나 완전히 해석하지 않으며, 명령 입력의 행동 순서만
검사한다. 같은 파일인지, 다운로드/실행이 성공했는지, 악성 행위인지는 보장하지
않는다. 따옴표/서브셸/변수 치환은 셸 파서 수준으로 해석하지 않는다. 시간 제한은
세션 경계뿐이다. 동일 시각의 별도 이벤트는 실제 순서가 맞아도 탐지되지 않을 수
있다. ingest가 저장하지 않는 더 세밀한 이벤트 순서를 임의로 만들지 않는다.
