# Slack 관리자 알림 전송 준비

## 현재 사용 가능

미리보기부터 열어 메시지의 날짜와 숫자를 확인한다. 이 명령은 Slack에 연결하지 않는다.

```powershell
python -m streamlit_app.slack_delivery --data-dir "work/operations/refresh-one-command-20261128"
```

## Slack 채널이 준비된 뒤

Slack에서 앱의 Incoming Webhook을 사용할 채널에 등록한다. 웹훅 주소는 이 명령을 실행할 환경의 `HONEYPOT_SLACK_WEBHOOK` 환경변수로만 전달한다. 주소를 파일이나 채팅에 붙여 넣지 않는다.

팀에서 테스트 전송을 승인한 뒤에만 아래 형태로 실행한다. `--data-dir`은 전송 대상을 확인한 갱신본, `--destination`은 채널을 구별하는 고정된 이름이다. 같은 채널에서는 다시 실행할 때도 같은 이름과 전송 기록 파일을 사용한다.

```powershell
python -m streamlit_app.slack_delivery --data-dir "<확인한 갱신본>" --send --destination "ops-test" --state "work/operations/slack-delivery.db"
```

`--send`가 없으면 미리보기만 표시한다. 실제 전송 기록은 별도 SQLite 파일에 저장하며, 미리보기 시험 기록과 분리한다. 메시지는 집계와 상태만 담는다.

- Slack이 성공 응답을 준 알림은 다시 보내지 않는다.
- Slack이 거부한 알림은 원인을 해결한 뒤 같은 명령으로 재시도할 수 있다. 그 전에 성공한 다른 메시지는 반복하지 않는다.
- 시간 초과처럼 이미 도착했는지 모르는 응답은 미확인으로 보존하고 자동 재전송하지 않는다. 채널에서 실제 도착 여부를 먼저 확인한다.

## 갱신 직후 전송까지 한 번에 실행

테스트 채널에서 실제 전송을 확인한 뒤 기존 갱신 명령에 아래 옵션을 추가한다.

```powershell
python -m streamlit_app.refresh_dashboard --seoul-logs "<서울 로그>" --syd-db "<시드니 DB>" --out "<새 갱신본>" --slack-send --slack-destination "ops-test" --slack-state "work/operations/slack-delivery.db"
```

갱신본 생성과 검증이 성공한 뒤에만 전송한다. Slack 전송에 실패해도 새 갱신본은 그대로 열 수 있다. 거부된 메시지를 다시 시험할 때는 새로 빌드하지 말고, 같은 갱신본·채널 이름·기록 파일을 지정해 위의 `slack_delivery` 명령으로 실행한다. `--slack-preview`만 주면 외부 전송 없이 메시지를 출력한다.

예약 실행을 설정하기 전에는 한 번의 테스트 전송으로 채널과 문구를 확인한다.
