@echo off
setlocal EnableExtensions

cd /d "%~dp0"

net session >nul 2>&1
if errorlevel 1 (
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -WorkingDirectory '%~dp0' -Verb RunAs"
    exit /b 0
)

set "INSTALL_DIR=%ProgramFiles%\AIVPN"
set "START_MENU_DIR=%ProgramData%\Microsoft\Windows\Start Menu\Programs\AIVPN"
set "DESKTOP_SHORTCUT=%Public%\Desktop\AIVPN.lnk"
set "START_MENU_SHORTCUT=%START_MENU_DIR%\AIVPN.lnk"
set "START_MENU_UNINSTALL_SHORTCUT=%START_MENU_DIR%\Uninstall AIVPN.lnk"

rem Upgrade over a running app: stop both processes first (otherwise the
rem copy fails with a sharing violation or leaves a mixed-version install),
rem and clear any kill-switch firewall rules the killed client leaves behind.
taskkill /IM aivpn.exe /F >nul 2>nul
taskkill /IM aivpn-client.exe /F >nul 2>nul
timeout /t 2 /nobreak >nul 2>nul
if exist "%INSTALL_DIR%\aivpn-client.exe" "%INSTALL_DIR%\aivpn-client.exe" kill-switch clear >nul 2>nul

echo Installing AIVPN to "%INSTALL_DIR%"...
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
if not exist "%START_MENU_DIR%" mkdir "%START_MENU_DIR%"

copy /Y "aivpn.exe" "%INSTALL_DIR%\aivpn.exe" >nul || goto :copy_error
copy /Y "aivpn-client.exe" "%INSTALL_DIR%\aivpn-client.exe" >nul || goto :copy_error
copy /Y "wintun.dll" "%INSTALL_DIR%\wintun.dll" >nul || goto :copy_error

call :write_uninstaller || goto :copy_error
call :create_shortcut "%INSTALL_DIR%\aivpn.exe" "%START_MENU_SHORTCUT%" "%INSTALL_DIR%"
call :create_shortcut "%INSTALL_DIR%\aivpn.exe" "%DESKTOP_SHORTCUT%" "%INSTALL_DIR%"
call :create_shortcut "%INSTALL_DIR%\uninstall.cmd" "%START_MENU_UNINSTALL_SHORTCUT%" "%INSTALL_DIR%"

echo.
echo AIVPN installation complete.
echo Installed files:
echo   %INSTALL_DIR%\aivpn.exe
echo   %INSTALL_DIR%\aivpn-client.exe
echo   %INSTALL_DIR%\wintun.dll
echo.
pause
exit /b 0

:copy_error
echo.
echo Installation failed while copying files.
pause
exit /b 1

:create_shortcut
powershell -NoProfile -ExecutionPolicy Bypass -Command "$shell = New-Object -ComObject WScript.Shell; $shortcut = $shell.CreateShortcut('%~2'); $shortcut.TargetPath = '%~1'; $shortcut.WorkingDirectory = '%~3'; $shortcut.IconLocation = '%~1,0'; $shortcut.Save()" >nul 2>&1
exit /b 0

:write_uninstaller
(
    echo @echo off
    echo setlocal EnableExtensions
    echo net session ^>nul 2^>^&1
    echo if errorlevel 1 ^(
    echo ^    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%%~f0' -WorkingDirectory '%%~dp0' -Verb RunAs"
    echo ^    exit /b 0
    echo ^)
    echo taskkill /IM aivpn.exe /F ^>nul 2^>nul
    echo taskkill /IM aivpn-client.exe /F ^>nul 2^>nul
    echo rem Clear kill-switch firewall rules BEFORE deleting the binary --
    echo rem taskkill bypasses the client's own cleanup, and after the del
    echo rem below nothing on the machine can remove the block-all rules.
    echo "%%~dp0aivpn-client.exe" kill-switch clear ^>nul 2^>nul
    echo del /F /Q "%%ProgramData%%\Microsoft\Windows\Start Menu\Programs\AIVPN\AIVPN.lnk" ^>nul 2^>nul
    echo del /F /Q "%%ProgramData%%\Microsoft\Windows\Start Menu\Programs\AIVPN\Uninstall AIVPN.lnk" ^>nul 2^>nul
    echo rmdir /Q "%%ProgramData%%\Microsoft\Windows\Start Menu\Programs\AIVPN" ^>nul 2^>nul
    echo del /F /Q "%%Public%%\Desktop\AIVPN.lnk" ^>nul 2^>nul
    echo del /F /Q "%%~dp0aivpn.exe" ^>nul 2^>nul
    echo del /F /Q "%%~dp0aivpn-client.exe" ^>nul 2^>nul
    echo del /F /Q "%%~dp0wintun.dll" ^>nul 2^>nul
    echo del /F /Q "%%~dp0uninstall.cmd" ^>nul 2^>nul
    echo cd /d "%%TEMP%%"
    echo rmdir /S /Q "%INSTALL_DIR%" ^>nul 2^>nul
    echo echo AIVPN removed.
    echo pause
) > "%INSTALL_DIR%\uninstall.cmd"
exit /b 0