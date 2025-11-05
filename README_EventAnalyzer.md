# Analizator Dziennika Zdarzeń Windows 11

Zaawansowane narzędzie do analizy dziennika zdarzeń Windows, które automatycznie kategoryzuje problemy według ważności i sugeruje rozwiązania.

## Funkcje

- **Automatyczna analiza** dzienników System, Application i Security
- **Priorytetyzacja zdarzeń** według ważności (Krytyczne, Błędy, Ostrzeżenia, Informacje)
- **Inteligentne sugestie rozwiązań** dla ponad 30 najczęstszych problemów Windows
- **Szczegółowe raporty** ze statystykami i rekomendacjami
- **Elastyczny zakres czasowy** analizy (ostatnie 24h, 48h, 7 dni lub własny)
- **Eksport raportów** w dwóch formatach:
  - **TXT** - format tekstowy do archiwizacji
  - **HTML** - nowoczesny raport z grafiką i kolorami ✨

## Wymagania

- Windows 11 (lub Windows 10)
- Python 3.7 lub nowszy
- Uprawnienia administratora (do odczytu dzienników zdarzeń)

## Instalacja

1. Sklonuj lub pobierz pliki projektu
2. Zainstaluj wymagane biblioteki:

```bash
pip install -r requirements.txt
```

## Użycie

### Uruchomienie podstawowe

Uruchom skrypt **jako Administrator** (w PowerShell lub CMD):

```bash
python windows_event_analyzer.py
```

### Opcje analizy

Po uruchomieniu skrypt zapyta o zakres czasowy:
- `1` - Ostatnie 24 godziny (domyślnie)
- `2` - Ostatnie 48 godzin
- `3` - Ostatnie 7 dni
- `4` - Własny zakres (podaj liczbę godzin)

### Przykład użycia

```bash
C:\Users\tomas> python windows_event_analyzer.py

================================================================================
ANALIZATOR DZIENNIKA ZDARZEŃ WINDOWS 11
================================================================================

Wybierz zakres czasowy analizy:
1. Ostatnie 24 godziny (domyślnie)
2. Ostatnie 48 godzin
3. Ostatnie 7 dni
4. Własny zakres

Wybór (1-4) [1]: 1

Rozpoczynam analizę ostatnich 24 godzin...
Analizuję dzienniki zdarzeń z ostatnich 24 godzin...

Czytam dziennik: System...
  Znaleziono 1847 zdarzeń

Czytam dziennik: Application...
  Znaleziono 943 zdarzeń

Czytam dziennik: Security...
  Znaleziono 2156 zdarzeń

[... raport ...]

Czy zapisać raport do pliku? (t/n) [t]: t

Wybierz format raportu:
1. TXT - Format tekstowy (domyślnie)
2. HTML - Format HTML z graficzną prezentacją
3. Oba formaty

Wybór (1-3) [1]: 2

Raport zapisany do pliku: event_log_report_20250105_143022.html
Otwórz plik w przeglądarce aby zobaczyć raport.
```

## Formaty raportów

### 📄 Format TXT
Klasyczny format tekstowy, idealny do:
- Archiwizacji długoterminowej
- Przetwarzania automatycznego (skrypty)
- Przeszukiwania za pomocą grep/findstr
- Wysyłania emailem
- Szybkiego przeglądu w edytorze tekstu

### 🎨 Format HTML (NOWOŚĆ!)
Nowoczesny, interaktywny raport z:
- **Responsywnym designem** - dostosowuje się do rozmiaru ekranu
- **Kolorowymi kartami statystyk** - gradient purple/blue
- **Interaktywnymi wykresami słupkowymi** - wizualizacja poziomów ważności
- **Szczegółowymi kartami błędów** - kolorowe ramki (czerwone dla krytycznych, pomarańczowe dla błędów)
- **Rozwijalnymi sekcjami** - kliknij aby zobaczyć pełną wiadomość zdarzenia
- **Gotowym do wydruku** - specjalne style @media print
- **Gradientowym tłem** - profesjonalny wygląd

Raport HTML zawiera wszystkie te same informacje co TXT, ale w znacznie bardziej przejrzystej i atrakcyjnej formie!

## Struktura raportu

Wygenerowany raport zawiera:

### 1. Podsumowanie statystyk
- Łączna liczba zdarzeń
- Podział według ważności (krytyczne, błędy, ostrzeżenia, informacje)

### 2. Top 10 najczęstszych zdarzeń
- Event ID i liczba wystąpień
- Krótki opis problemu

### 3. Szczegółowa analiza zdarzeń krytycznych i błędów
Dla każdego problemu:
- Event ID i ważność
- Liczba wystąpień
- Źródło i dziennik
- Czas ostatniego wystąpienia
- **Opis problemu**
- **Zalecane rozwiązania** (krok po kroku)
- Przykładowa wiadomość zdarzenia

### 4. Podsumowanie ostrzeżeń
- Lista 15 najczęstszych ostrzeżeń

### 5. Rekomendacje końcowe
- Pilne akcje do wykonania
- Ogólne zalecenia konserwacyjne

## Obsługiwane Event ID i rozwiązania

Skrypt zawiera rozszerzoną bazę wiedzy dla 33+ najczęstszych problemów Windows:

### Problemy systemowe
- **6008** - Nieoczekiwane wyłączenie systemu (KRYTYCZNE)
- **1001** - BugCheck (BSOD) (KRYTYCZNE)
- **7000/7001** - Problemy z uruchamianiem usług
- **10016** - Błędy uprawnień DCOM
- **10010** - DCOM - Serwer nie zarejestrował się
- **1** - Usługa Event Log uruchomiona (informacyjne)
- **1072** - Restart/wyłączenie zainicjowane przez użytkownika
- **1074** - System zamknięty przez użytkownika/aplikację
- **7040** - Zmieniono typ uruchamiania usługi
- **1801** - TPM/Secure Boot - wymagana aktualizacja certyfikatów

### Problemy aplikacji
- **1000** - Awaria aplikacji
- **1002** - Aplikacja przestała odpowiadać
- **78** - SideBySide - konflikt wersji składników
- **13** - VSS - błąd usługi kopiowania woluminów
- **8193** - VSS - błąd CoCreateInstance
- **1023** - Perflib - nie można załadować DLL licznika
- **153** - Błąd sterownika NVIDIA GPU

### Problemy dyskowe (KRYTYCZNE!)
- **7** - Błąd odczytu/zapisu dysku
- **51** - Ostrzeżenie o błędzie dysku

### Bezpieczeństwo i audyt
- **4624** - Udane logowanie
- **4625** - Nieudana próba logowania
- **4672** - Przypisano specjalne uprawnienia (admin logon)
- **4798** - Wyliczono członkostwo w grupie lokalnej
- **4799** - Wyliczono członkostwo w grupie zabezpieczonej
- **4907** - Zmieniono ustawienia audytu obiektu
- **5058** - Operacja na pliku klucza kryptograficznego
- **5061** - Operacja kryptograficzna
- **5379** - Odczytano poświadczenia Credential Manager

### Problemy sieciowe
- **5719** - Nie można połączyć się z kontrolerem domeny
- **1014** - Błąd rozpoznawania DNS

**Uwaga:** Większość zdarzeń Security (4xxx, 5xxx) to normalne zdarzenia audytu - nie wymagają działania, służą tylko do monitoringu!

## Rozszerzanie bazy wiedzy

Możesz łatwo dodać własne rozwiązania edytując klasę `SolutionDatabase` w pliku:

```python
class SolutionDatabase:
    SOLUTIONS = {
        12345: {  # Nowy Event ID
            "description": "Opis problemu",
            "severity": EventSeverity.ERROR,
            "solutions": [
                "Rozwiązanie 1",
                "Rozwiązanie 2",
                "Rozwiązanie 3"
            ]
        },
        # ... więcej
    }
```

## Najlepsze praktyki

1. **Uruchamiaj jako Administrator** - wymagane do odczytu dzienników
2. **Regularnie analizuj** - zalecane codzienne lub cotygodniowe sprawdzanie
3. **Zachowuj raporty** - przydatne do śledzenia trendów
4. **Reaguj na zdarzenia krytyczne** - szczególnie problemy z dyskiem!
5. **Monitoruj próby logowania** - wykrywaj potencjalne próby włamania

## Rozwiązywanie problemów

### "Błąd: Access Denied"
- Uruchom skrypt jako Administrator
- Kliknij prawym przyciskiem na PowerShell/CMD → "Uruchom jako administrator"

### "ModuleNotFoundError: No module named 'win32evtlog'"
```bash
pip install pywin32
# lub
pip install --upgrade pywin32
```

### Skrypt działa bardzo wolno
- Zmniejsz zakres czasowy analizy
- Dzienniki Security mogą zawierać bardzo dużo zdarzeń
- Rozważ filtrowanie tylko określonych dzienników

## Użycie programistyczne

Możesz użyć analizatora w swoich skryptach:

```python
from windows_event_analyzer import WindowsEventAnalyzer

# Utwórz analizator dla ostatnich 24 godzin
analyzer = WindowsEventAnalyzer(hours_back=24)

# Przeprowadź analizę
analyzer.analyze_events()

# Pobierz zdarzenia
events = analyzer.events

# === GENEROWANIE RAPORTÓW ===

# Raport tekstowy
analyzer.save_report("raport.txt", format='txt')

# Raport HTML ✨
analyzer.save_report("raport.html", format='html')

# Oba formaty
analyzer.save_report("raport.txt", format='txt')
analyzer.save_report("raport.html", format='html')

# Pobierz raport jako string
report_text = analyzer.generate_report()      # TXT
report_html = analyzer.generate_html_report()  # HTML

print(report_text)
```

### Przykład: Automatyczne codzienne raporty HTML

```python
from windows_event_analyzer import WindowsEventAnalyzer
from datetime import datetime

# Generuj raport
analyzer = WindowsEventAnalyzer(hours_back=24)
analyzer.analyze_events()

# Zapisz z datą w nazwie
today = datetime.now().strftime('%Y%m%d')
analyzer.save_report(f"daily_report_{today}.html", format='html')

# Możesz też wysłać emailem lub skopiować na serwer
```

## Bezpieczeństwo

- Skrypt tylko **odczytuje** dzienniki - nie modyfikuje żadnych ustawień
- Nie wysyła żadnych danych przez sieć
- Wszystkie raporty są zapisywane lokalnie
- Kod jest otwarty do przejrzenia i audytu

## Przydatne komendy Windows

Skrypt sugeruje różne komendy. Oto jak je uruchomić:

```bash
# Skanowanie integralności plików systemowych
sfc /scannow

# Sprawdzanie dysku
chkdsk /f /r

# Czyszczenie cache DNS
ipconfig /flushdns

# Sprawdzanie statusu dysków
wmic diskdrive get status

# Test pamięci RAM
mdsched.exe
```

## Dalszy rozwój

Potencjalne ulepszenia:
- [ ] Eksport do HTML/JSON
- [ ] Monitoring w czasie rzeczywistym
- [ ] Integracja z notyfikacjami email
- [ ] Dashboard webowy
- [ ] Filtrowanie według źródeł zdarzeń
- [ ] Eksport wykresów i statystyk
- [ ] Baza wiedzy aktualizowana online

## Licencja

Ten projekt jest dostępny na licencji open-source. Możesz go swobodnie używać, modyfikować i dystrybuować.

## Autor

Stworzony przez Claude Code - Anthropic

## Wsparcie

Jeśli napotkasz problemy:
1. Sprawdź czy uruchamiasz jako Administrator
2. Zweryfikuj instalację pywin32
3. Sprawdź czy Event Viewer działa poprawnie w systemie
4. Przejrzyj sekcję "Rozwiązywanie problemów" powyżej

---

**Ważne:** Ten skrypt jest narzędziem pomocniczym. W przypadku poważnych problemów systemowych zalecane jest skonsultowanie się z profesjonalnym administratorem systemu lub wsparciem technicznym Microsoft.
