@echo off
rem Streamlit 허니팟 대시보드 실행 (Windows). 저장소 루트에서 더블클릭하거나 실행한다.
rem 처음 한 번: python -m venv .venv  &&  .venv\Scripts\python -m pip install -r streamlit_app\requirements.txt -r ml\requirements.txt
rem 데이터 만들기: .venv\Scripts\python streamlit_app\build_db.py --seoul-logs <서울 로그 폴더> --syd-db <시드니 DB> --geo work\geo\dbip-country-ipv4.csv --ml
chcp 65001 >nul
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo [안내] .venv가 없습니다. 위 주석의 설치 명령을 먼저 실행하세요.
  pause
  exit /b 1
)
if not exist "data\dashboard\dashboard.db" (
  echo [안내] data\dashboard\dashboard.db가 없습니다. build_db.py로 데이터를 먼저 만드세요.
  pause
  exit /b 1
)
echo 대시보드를 시작합니다: http://localhost:8501  (종료: Ctrl+C)
".venv\Scripts\python.exe" -m streamlit run streamlit_app\app.py --server.port 8501
