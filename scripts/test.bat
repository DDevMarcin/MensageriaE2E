@echo off
setlocal
cd /d "%~dp0\.."

call "%~dp0\build.bat"
if errorlevel 1 exit /b %ERRORLEVEL%

java -cp out securechat.TestRunner %*
exit /b %ERRORLEVEL%

