@echo off
setlocal EnableExtensions EnableDelayedExpansion

rem Anchor everything to this script's own directory so double-clicking
rem from any cwd works.
cd /d "%~dp0"

set "CONFIG_FILE=%~dp0config.txt"
set "TARGET_HOST="

if not exist "%CONFIG_FILE%" (
    echo ERROR: config.txt is missing from this folder.
    echo Please re-download the SDG Connection Test bundle, or contact SDG support.
    echo.
    pause
    exit /b 1
)

rem Parse config.txt: ignore blank lines and lines starting with #.
for /f "usebackq eol=# tokens=1,* delims==" %%A in ("%CONFIG_FILE%") do (
    set "KEY=%%A"
    set "VAL=%%B"
    rem Trim leading/trailing whitespace on key and value.
    for /f "tokens=* delims= " %%K in ("!KEY!") do set "KEY=%%K"
    for /f "tokens=* delims= " %%V in ("!VAL!") do set "VAL=%%V"
    if /i "!KEY!"=="TARGET_HOST" set "TARGET_HOST=!VAL!"
)

if not defined TARGET_HOST (
    echo ERROR: TARGET_HOST is not set in config.txt.
    echo Please re-download the SDG Connection Test bundle, or contact SDG support.
    echo.
    pause
    exit /b 1
)

set "NODE_EXE=%~dp0app\node.exe"
set "CLIENT_JS=%~dp0app\client\client.js"

if not exist "%NODE_EXE%" (
    echo ERROR: bundled Node runtime not found at app\node.exe
    echo The bundle appears incomplete. Please re-download.
    echo.
    pause
    exit /b 1
)

if not exist "%CLIENT_JS%" (
    echo ERROR: client.js not found at app\client\client.js
    echo The bundle appears incomplete. Please re-download.
    echo.
    pause
    exit /b 1
)

rem Build a timestamped report path next to this script. Writing to the
rem script's own folder dodges every Desktop-resolution edge case
rem (OneDrive Known Folder Move, group-policy redirection, sign-in-as-
rem different-user). The user already extracted the bundle into a
rem folder they can find — drop the report there.
rem
rem Use the bundled Node via a temp file to dodge cmd's for /f quoting
rem problems (and wmic, which is removed on Windows 11 24H2+).
set "TS_FILE=%TEMP%\sdg-ts-%RANDOM%.txt"
"%NODE_EXE%" -e "process.stdout.write(new Date().toISOString().replace(/[:.]/g,'-').slice(0,19))" > "%TS_FILE%" 2>nul
set "TS="
if exist "%TS_FILE%" set /p "TS="<"%TS_FILE%"
if exist "%TS_FILE%" del "%TS_FILE%" 2>nul
if not defined TS set "TS=run"
set "REPORT=%~dp0sdg-test-report-%TS%.json"

echo ============================================================
echo   SDG Connection Test
echo ============================================================
echo.
echo   Target server : %TARGET_HOST%
echo   Report file   : %REPORT%
echo.
echo   This test takes about 3 to 4 minutes.
echo   Please leave this window open until it finishes.
echo.
echo ============================================================
echo.

"%NODE_EXE%" "%CLIENT_JS%" --host %TARGET_HOST% --yes --json "%REPORT%"
set "RC=%ERRORLEVEL%"

echo.
echo ============================================================
if %RC% EQU 0 (
    echo   Test complete. Report saved to:
    echo   %REPORT%
    echo.
    echo   Please attach this file to your SDG support ticket.
) else (
    echo   Test exited with code %RC%.
    if exist "%REPORT%" (
        echo   A partial report was saved to:
        echo   %REPORT%
        echo   Please send it to SDG support along with the messages above.
    ) else (
        echo   No report file was produced. Please send a screenshot of
        echo   this window to SDG support.
    )
)
echo ============================================================
echo.

pause
exit /b %RC%
