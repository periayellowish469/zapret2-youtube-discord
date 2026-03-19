@echo off
%SystemRoot%\System32\chcp.com 65001 >nul 2>&1
:: Запуск тестирования пресетов с обходом политики выполнения PowerShell
:: Можно запускать двойным кликом — права администратора будут запрошены автоматически

set "SYS32=%SystemRoot%\System32"
set "PS_EXE=%SYS32%\WindowsPowerShell\v1.0\powershell.exe"

%SYS32%\net.exe session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Требуются права администратора. Перезапуск...
    %PS_EXE% -NoProfile -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

%PS_EXE% -NoProfile -ExecutionPolicy Bypass -File "%~dp0test-presets.ps1"
