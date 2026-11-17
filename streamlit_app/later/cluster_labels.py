"""군집 번호의 해석 (사람이 붙인 이름).

군집 번호는 fit할 때마다 바뀔 수 있으므로 이 해석은 FITTED_AT의 fit 결과에만 맞는다.
대시보드는 DB의 ml_clusters fit 시각이 다르면 경고를 띄운다. 다시 fit하면 이 파일도 고친다.
출처: data/syd_20261109/DATA_HANDOFF.md 5절 (2026-11-09 전달).
"""

FITTED_AT = '2026-11-09T04:37:30+00:00'

LABELS = {
    0: {'short': '장비 확인 (HISILICON)',
        'detail': '`sh ; shell ; enable ; system ; ping` 후 `/bin/busybox HISILICON`, '
                  '`cat /proc/self/exe`. 자기 실행 파일을 읽어 아키텍처를 확인하는 것으로 추정. '
                  '거의 항상 2초 뒤 같은 IP의 1번이 이어진다.'},
    1: {'short': '쓰기 가능 위치 탐색 (.f)',
        'detail': '0번과 같은 시작 뒤 `>/var/.f ; chmod 777 /var/.f ; /var/.f`를 여러 디렉터리에서 반복. '
                  '쓰기·실행 가능한 위치 탐색으로 추정. 0→1이 같은 봇의 한 공격이다.'},
    2: {'short': 'PBOC 도구 (고장 버전)',
        'detail': '`/bin/busybox hostname PBOC` 후 `.k` 스크립트를 hex로 기록하지만 문법 오류로 깨져 '
                  '실행 기록이 없다. PBOC 도구의 고장 버전으로 추정.'},
    3: {'short': 'PBOC 도구 (경쟁 프로세스 제거)',
        'detail': '2번과 같은 시작 뒤 `.k`에 `/proc/*/exe`가 (deleted)인 프로세스를 `kill -9`하는 '
                  '스크립트를 쓰고 `sh .k`를 10회 실행. 규칙 B12 100%.'},
    4: {'short': '.ptmx 드로퍼 (HolyFuck)',
        'detail': '`>/tmp/.ptmx ; cd /tmp/ …`를 13개 디렉터리에서 반복한 뒤 `/bin/busybox HolyFuck`. '
                  'IP 하나뿐이며 그 IP는 다른 세션들의 다운로드 서버 주소와 같다.'},
    5: {'short': '짧은 탐색 (SORA/LZRD)',
        'detail': '`shell ; sh` (+ `/bin/busybox SORA` 또는 `LZRD`). Mirai 변종 이름 확인으로 추정.'},
    -1: {'short': '노이즈 (미분류)',
         'detail': '어느 군집에도 속하지 않은 세션. 728개 명령짜리 dvrHelper 변형(실제 다운로드), '
                   'KYTON·OWARI·FICORA 같은 다른 변종 이름, HTTP·SIP 스캐너 입력이 섞여 있다.'},
}
