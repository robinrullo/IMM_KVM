@echo off
setlocal
echo =========================================
echo Building Windows package using PyInstaller
echo =========================================

REM Build the executable
pyinstaller imm_kvm_windows.spec

IF %ERRORLEVEL% NEQ 0 (
    echo PyInstaller failed!
    exit /b %ERRORLEVEL%
)

echo =========================================
echo Windows build complete!
echo Output folder: %TARGET_DIR%
echo =========================================

endlocal
pause
