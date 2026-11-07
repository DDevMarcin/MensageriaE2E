@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0\.."

if not exist out mkdir out

set "SOURCES_FILE=out\sources.txt"
if exist "%SOURCES_FILE%" del /q "%SOURCES_FILE%"

for /r src %%f in (*.java) do (
    set "P=%%f"
    echo "!P:\=/!" >> "%SOURCES_FILE%"
)
for /r test %%f in (*.java) do (
    set "P=%%f"
    echo "!P:\=/!" >> "%SOURCES_FILE%"
)

javac -Xlint:all --release 21 -encoding UTF-8 -d out @"%SOURCES_FILE%"
set "ERR=%ERRORLEVEL%"
if exist "%SOURCES_FILE%" del /q "%SOURCES_FILE%"
exit /b %ERR%

