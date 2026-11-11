@echo off
cd /d "%~dp0"

py -m pip install --upgrade pip
if errorlevel 1 exit /b 1

py -m pip install -r requirements.txt
if errorlevel 1 exit /b 1

py -m pip install pyinstaller
if errorlevel 1 exit /b 1

py -m PyInstaller --noconfirm --clean OpenPagingServerDesktop.spec
if errorlevel 1 exit /b 1

set "OPS_ISCC="
for /f "delims=" %%I in ('where ISCC.exe 2^>nul') do if not defined OPS_ISCC set "OPS_ISCC=%%I"
if not defined OPS_ISCC if exist "%ProgramFiles%\Inno Setup 7\ISCC.exe" set "OPS_ISCC=%ProgramFiles%\Inno Setup 7\ISCC.exe"
if not defined OPS_ISCC if exist "%ProgramFiles%\Inno Setup 6\ISCC.exe" set "OPS_ISCC=%ProgramFiles%\Inno Setup 6\ISCC.exe"
if not defined OPS_ISCC if exist "%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe" set "OPS_ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if not defined OPS_ISCC (
    echo Inno Setup compiler ISCC.exe was not found.
    exit /b 1
)

"%OPS_ISCC%" installer.iss
if errorlevel 1 exit /b 1

echo.
echo Build complete: dist\OpenPagingServerClient.exe
echo Installer complete: dist\OpenPagingServerClientSetup.exe
