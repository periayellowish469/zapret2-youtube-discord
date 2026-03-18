@echo off

C:\Windows\System32\net.exe session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator privileges...
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "%~f0", "", "", "runas", 1 >> "%temp%\getadmin.vbs"
    C:\Windows\System32\cscript.exe //nologo "%temp%\getadmin.vbs"
    C:\Windows\System32\cmd.exe /c del "%temp%\getadmin.vbs"
    exit /b
)

C:\Windows\System32\taskkill.exe /F /IM winws.exe /T
C:\Windows\System32\taskkill.exe /F /IM winws2.exe /T
C:\Windows\System32\sc.exe stop Monkey
C:\Windows\System32\sc.exe delete Monkey
exit /b