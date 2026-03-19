@echo off
:: Запуск winws2 с активным пресетом
:: Этот файл вызывается для ручного запуска и отладки
:: Для автозапуска (Task Scheduler) используется zapret2-start.vbs
cd /d "%~dp0.."

set "SYS32=%SystemRoot%\System32"

:: Очистка WinDivert перед запуском (предотвращает ошибки сертификатов)
for %%s in (WinDivert WinDivert14 Monkey Monkey14) do (
    %SYS32%\sc.exe query "%%s" >nul 2>&1 && (
        %SYS32%\net.exe stop "%%s" >nul 2>&1
        %SYS32%\sc.exe delete "%%s" >nul 2>&1
    )
)

:: Включаем TCP timestamps
%SYS32%\netsh.exe interface tcp set global timestamps=enabled >nul 2>&1

:: Пауза после очистки
%SYS32%\timeout.exe /t 1 /nobreak >nul

exe\winws2.exe @utils\preset-active.txt
