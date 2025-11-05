@echo off
chcp 65001 >nul

REM Przejdź do katalogu skryptu
cd /d "%~dp0"

echo ================================================================================
echo    INSTALACJA ANALIZATORA DZIENNIKA ZDARZEŃ WINDOWS
echo ================================================================================
echo.

REM Sprawdź czy Python jest zainstalowany
python --version >nul 2>&1
if errorlevel 1 (
    echo [BŁĄD] Python nie jest zainstalowany!
    echo.
    echo Pobierz i zainstaluj Python z: https://www.python.org/downloads/
    echo Upewnij się, że zaznaczasz opcję "Add Python to PATH" podczas instalacji.
    echo.
    pause
    exit /b 1
)

echo [OK] Wykryto Pythona:
python --version
echo.

REM Sprawdź czy pip jest dostępny
pip --version >nul 2>&1
if errorlevel 1 (
    echo [BŁĄD] pip nie jest dostępny!
    echo.
    pause
    exit /b 1
)

echo [OK] Wykryto pip:
pip --version
echo.

echo Instaluję wymagane biblioteki...
echo.

pip install -r requirements.txt

if errorlevel 1 (
    echo.
    echo [BŁĄD] Instalacja nie powiodła się!
    echo.
    pause
    exit /b 1
)

echo.
echo ================================================================================
echo    INSTALACJA ZAKOŃCZONA POMYŚLNIE!
echo ================================================================================
echo.
echo Aby uruchomić analizator:
echo   1. Otwórz PowerShell lub CMD jako Administrator
echo   2. Przejdź do katalogu: cd "%~dp0"
echo   3. Uruchom: python windows_event_analyzer.py
echo.
echo Lub użyj pliku uruchom.bat (uruchom jako Administrator)
echo.
pause
