# 새 후보 관리자 알림

후보 저장소에서 검토 대기인 후보를 골라 요약과 함께 미리 볼 수 있다.

```powershell
python -m streamlit_app.slack_delivery --data-dir "work/operations/refresh-local-proposals-20261128" --include-candidates
```

실제 발송은 같은 명령에 기존의 `--send --destination <채널이름> --state <발송기록.db>` 옵션을 추가한다. 갱신 직후까지 연결하려면 갱신 명령에 `--slack-preview --slack-candidates` 또는 `--slack-send --slack-candidates`를 사용한다.

알림에는 후보의 짧은 ID, 프로토콜, 전체 일치 건수, 기존 구체 규칙과 중복되는 건수와 검토 화면 안내를 넣는다. 초안 명령과 IP는 보내지 않는다. 같은 발송 기록 파일, 채널 이름, 데이터 출처 조합을 유지하면 같은 후보는 한 번만 알린다. 발송 기록 없이 미리보기만 실행하면 검토 대기 후보 목록 전체가 표시된다.

현재 알림 대상은 로컬 예시 로직으로 만든 후보다. 이 단계의 알림을 실제 채널로 보내려면 미리보기 내용을 확인한 후 발송한다.
