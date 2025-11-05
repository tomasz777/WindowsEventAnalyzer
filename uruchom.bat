@echo off
chcp 65001 >nul

REM Sprawdź uprawnienia administratora
net session >nul 2>&1
if errorlevel 1 (
    echo ================================================================================
    echo    BŁĄD: Brak uprawnień administratora!
    echo ================================================================================
    echo.
    echo Ten skrypt wymaga uprawnień administratora do odczytu dzienników zdarzeń.
    echo.
    echo Jak uruchomić jako Administrator:
    echo   1. Kliknij prawym przyciskiem myszy na plik uruchom.bat
    echo   2. Wybierz "Uruchom jako administrator"
    echo.
    pause
    exit /b 1
)

REM Przejdź do katalogu skryptu
cd /d "%~dp0"

REM Uruchom analizator
python windows_event_analyzer.py

pause
