# Przewodnik Event ID Windows

Kompletna lista wszystkich Event ID obsługiwanych przez Windows Event Analyzer z wyjaśnieniami.

## 📋 Spis treści

- [Zdarzenia Krytyczne](#zdarzenia-krytyczne)
- [Błędy](#błędy)
- [Ostrzeżenia](#ostrzeżenia)
- [Informacyjne](#informacyjne)

---

## 🔴 Zdarzenia Krytyczne

Te zdarzenia wymagają natychmiastowej uwagi!

### Event ID 6008 - Nieoczekiwane wyłączenie systemu
**Co to znaczy:** System został wyłączony bez prawidłowej procedury shutdown (np. utrata zasilania, zawieszenie się)

**Przyczyny:**
- Problemy z zasilaniem
- Przegrzanie komponentów
- Błąd krytyczny systemu (BSOD)
- Awaria sprzętu

**Co zrobić:**
1. Sprawdź stabilność zasilania (UPS, gniazdko)
2. Zweryfikuj temperatury CPU i GPU
3. Sprawdź logi BSOD w Reliability Monitor
4. Zaktualizuj sterowniki

---

### Event ID 1001 - BugCheck (BSOD)
**Co to znaczy:** System wykrył błąd krytyczny i wykonał Blue Screen of Death

**Przyczyny:**
- Uszkodzona pamięć RAM
- Błędne sterowniki
- Problemy sprzętowe
- Uszkodzone pliki systemowe

**Co zrobić:**
1. Uruchom `sfc /scannow` jako Administrator
2. Sprawdź pamięć RAM za pomocą Windows Memory Diagnostic
3. Zaktualizuj wszystkie sterowniki
4. Sprawdź kod STOP w szczegółach zdarzenia

---

### Event ID 7 - Błąd odczytu/zapisu dysku
**Co to znaczy:** ⚠️ PILNE - Dysk ma problemy z odczytem lub zapisem danych

**Przyczyny:**
- Dysk zbliża się do awarii
- Uszkodzone sektory
- Problemy z kontrolerem SATA
- Uszkodzony kabel

**Co zrobić:**
1. **NATYCHMIAST wykonaj backup danych!**
2. Uruchom `chkdsk /f /r` jako Administrator
3. Sprawdź stan SMART dysku (CrystalDiskInfo)
4. Zaplanuj wymianę dysku
5. Nie ignoruj tego błędu - ryzyko utraty danych!

---

### Event ID 51 - Ostrzeżenie o błędzie dysku
**Co to znaczy:** ⚠️ PILNE - Dysk wykrył błąd i może wkrótce ulec awarii

**Przyczyny:**
- Zbliżająca się awaria dysku
- Uszkodzenie powierzchni magnetycznej
- Mechaniczne problemy (HDD)

**Co zrobić:**
1. **NATYCHMIAST wykonaj backup!**
2. Sprawdź SMART disk health
3. Zaplanuj wymianę dysku
4. To ostatnie ostrzeżenie przed całkowitą awarią

---

## 🟠 Błędy

Problemy wymagające uwagi, ale nie są krytyczne.

### Event ID 1000 - Awaria aplikacji
**Co to znaczy:** Aplikacja uległa awarii i została zamknięta

**Przyczyny:**
- Błąd w kodzie aplikacji
- Brak wymaganych bibliotek
- Niekompatybilność z Windows 11
- Uszkodzone pliki aplikacji

**Co zrobić:**
1. Zaktualizuj aplikację do najnowszej wersji
2. Przeinstaluj aplikację
3. Sprawdź zgodność z Windows 11
4. Zainstaluj brakujące .NET lub Visual C++ Redistributables

---

### Event ID 7000 - Usługa nie uruchomiła się
**Co to znaczy:** Systemowa usługa nie może się uruchomić

**Przyczyny:**
- Brak zależnych usług
- Nieprawidłowe uprawnienia
- Uszkodzone pliki usługi
- Błędna konfiguracja

**Co zrobić:**
1. Otwórz `services.msc`
2. Sprawdź zależności usługi
3. Zweryfikuj typ uruchamiania
4. Sprawdź uprawnienia konta usługi

---

## 🟡 Ostrzeżenia

Potencjalne problemy do monitorowania.

### Event ID 10016 - Błąd uprawnień DCOM
**Co to znaczy:** Komponent DCOM nie ma odpowiednich uprawnień

**Czy to problem:** ❌ NIE - To znany, nieszkodliwy problem Windows

**Co zrobić:**
- W większości przypadków **można zignorować**
- Jeśli chcesz naprawić: Component Services → DCOM Config → nadaj uprawnienia
- Nie wpływa na działanie systemu

---

### Event ID 10010 - DCOM - Serwer nie zarejestrował się
**Co to znaczy:** Serwer DCOM nie odpowiedział w wymaganym czasie

**Czy to problem:** ❌ NIE - Typowy, nieszkodliwy problem Windows

**Co zrobić:**
- **Zazwyczaj można bezpiecznie zignorować**
- Może być związane z RuntimeBroker lub ShellHWDetection
- Nie wpływa na stabilność systemu

---

### Event ID 78 - SideBySide - Błąd konfiguracji
**Co to znaczy:** Aplikacja ma konflikt wersji składników (DLL manifests)

**Przyczyny:**
- Brak wymaganych Visual C++ Redistributables
- Konflikt wersji bibliotek systemowych
- Uszkodzona instalacja aplikacji

**Co zrobić:**
1. Przeinstaluj aplikację
2. Zainstaluj najnowsze Visual C++ Redistributables
3. Sprawdź zgodność z Windows 11

---

### Event ID 13, 8193 - VSS - Błąd usługi kopiowania woluminów
**Co to znaczy:** Volume Shadow Copy Service ma problem (często podczas wyłączania)

**Czy to problem:** ❌ NIE - Zazwyczaj nieszkodliwe

**Co zrobić:**
- Często występuje podczas zamykania systemu - **można zignorować**
- Jeśli problem się powtarza, zrestartuj usługę VSS
- Sprawdź: `vssadmin list writers`

---

### Event ID 1023 - Perflib - Błąd biblioteki DLL licznika
**Co to znaczy:** Nie można załadować biblioteki licznika wydajności (sysmain.dll)

**Co zrobić:**
1. Uruchom `lodctr /R` aby przebudować liczniki
2. Sprawdź integralność: `sfc /scannow`
3. Może być związane z usługą SysMain

---

### Event ID 153 - Błąd sterownika NVIDIA
**Co to znaczy:** Sterownik karty graficznej NVIDIA zgłosił błąd

**Przyczyny:**
- Przestarzałe sterowniki
- Problemy z zasilaniem GPU
- Przegrzanie karty
- Przetaktowanie

**Co zrobić:**
1. Zaktualizuj sterowniki NVIDIA
2. Użyj DDU i przeinstaluj sterowniki
3. Sprawdź temperatury GPU
4. Zweryfikuj zasilanie karty

---

### Event ID 4625 - Nieudana próba logowania
**Co to znaczy:** Ktoś próbował się zalogować z nieprawidłowym hasłem

**Kiedy się martwić:**
- **Wiele prób (>10)** - możliwa próba włamania!
- Próby z nieznanych IP (zdalne połączenia)
- Logowania w nietypowych godzinach

**Co zrobić:**
1. Sprawdź szczegóły zdarzenia (kto, skąd, kiedy)
2. Zweryfikuj hasła kont
3. Rozważ wdrożenie 2FA
4. Sprawdź polityki bezpieczeństwa

---

### Event ID 1014 - Błąd rozpoznawania DNS
**Co to znaczy:** System nie może rozpoznać nazwy domeny na adres IP

**Przyczyny:**
- Problemy z serwerem DNS
- Błędne ustawienia DNS
- Problemy z połączeniem internetowym

**Co zrobić:**
1. Sprawdź ustawienia DNS w karcie sieciowej
2. Wypróbuj publiczne DNS (8.8.8.8, 1.1.1.1)
3. Wyczyść cache: `ipconfig /flushdns`
4. Zrestartuj usługę DNS Client

---

### Event ID 1801 - TPM/Secure Boot - Aktualizacja certyfikatów
**Co to znaczy:** Windows potrzebuje zaktualizowanych certyfikatów Secure Boot

**Czy to problem:** ❌ NIE - Informacyjne

**Co zrobić:**
- Windows Update zaktualizuje automatycznie
- System działa normalnie
- Sprawdź aktualizacje Windows Update

---

## ⚪ Informacyjne

Normalne zdarzenia systemowe - tylko do monitoringu.

### Event ID 4624 - Udane logowanie
**Co to znaczy:** Użytkownik zalogował się pomyślnie

**Czy to problem:** ❌ NIE - Normalne zdarzenie audytu

**Co monitorować:**
- Logowania w nietypowych godzinach
- Logowania zdalne (Type 10)
- Logowania z nieznanych lokalizacji

---

### Event ID 4672 - Przypisano specjalne uprawnienia
**Co to znaczy:** Użytkownik z prawami administratora się zalogował

**Czy to problem:** ❌ NIE - Normalne zdarzenie audytu

**Co zrobić:**
- Brak działania - to informacja audytowa
- Monitoruj nietypowe wzorce
- Pojawia się przy każdym logowaniu admina

---

### Event ID 4798, 4799 - Wyliczono członkostwo w grupach
**Co to znaczy:** System sprawdził do jakich grup należy użytkownik

**Czy to problem:** ❌ NIE - Normalne zdarzenie audytu

**Co zrobić:**
- Brak działania - standardowy audyt uprawnień
- Występuje podczas sprawdzania dostępu do zasobów

---

### Event ID 4907 - Zmieniono ustawienia audytu
**Co to znaczy:** Ktoś zmienił ustawienia audytu plików/folderów

**Czy to problem:** ❌ NIE - Informacyjne

**Co zrobić:**
- Przydatne do śledzenia zmian w polityce bezpieczeństwa
- Normalne podczas zmian uprawnień NTFS

---

### Event ID 5058, 5061 - Operacje kryptograficzne
**Co to znaczy:** System wykonał operację kryptograficzną

**Czy to problem:** ❌ NIE - Normalne zdarzenia audytu

**Związane z:**
- Windows Hello
- BitLocker
- Certyfikaty
- HTTPS/SSL

**Co zrobić:** Brak działania - standardowy audyt kryptografii

---

### Event ID 5379 - Odczytano poświadczenia Credential Manager
**Co to znaczy:** Aplikacja odczytała zapisane hasło z Credential Manager

**Czy to problem:** ❌ NIE - Normalne

**Kiedy występuje:**
- Podczas logowania do aplikacji
- Używanie zapisanych haseł przeglądarki
- Automatyczne logowanie do usług

**Co zrobić:** Monitoruj tylko nietypowe wzorce dostępu

---

### Event ID 1 - Usługa Event Log uruchomiona
**Co to znaczy:** System dziennika zdarzeń został uruchomiony

**Czy to problem:** ❌ NIE - Informacyjne

**Co zrobić:**
- To pierwsze zdarzenie po starcie systemu
- Oznacza że logging działa poprawnie

---

### Event ID 1072, 1074 - Wyłączenie/restart systemu
**Co to znaczy:** Użytkownik wyłączył lub zrestartował komputer

**Czy to problem:** ❌ NIE - Normalne

**Co zrobić:**
- Rejestruje kto i kiedy wyłączył system
- Przydatne do audytu aktywności
- Różni się od Event ID 6008 (nieoczekiwane wyłączenie)

---

### Event ID 7040 - Zmieniono typ uruchamiania usługi
**Co to znaczy:** Ktoś zmienił konfigurację usługi (np. z automatycznej na ręczną)

**Czy to problem:** Zależy - sprawdź czy zmiana była zamierzona

**Co zrobić:**
- Sprawdź szczegóły zdarzenia
- Zweryfikuj czy zmiana była autoryzowana
- Monitoruj zmiany w krytycznych usługach

---

## 🔍 Jak używać tego przewodnika

### W raporcie widzisz Event ID?
1. Znajdź Event ID w tym przewodniku
2. Sprawdź czy to problem (🔴/🟠/🟡/⚪)
3. Przeczytaj "Co to znaczy"
4. Wykonaj sugerowane działania

### Jak priorytetyzować?
- 🔴 **Krytyczne** - działaj natychmiast!
- 🟠 **Błędy** - zbadaj i napraw
- 🟡 **Ostrzeżenia** - monitoruj
- ⚪ **Informacyjne** - tylko do audytu

### Najczęstsze pytania

**Q: Mam 10,000 zdarzeń Security - czy to problem?**
A: NIE! Większość to normalne zdarzenia audytu (4xxx, 5xxx). Ignoruj zdarzenia informacyjne.

**Q: Event ID 10016 pojawia się setki razy**
A: To znany, nieszkodliwy problem Windows. Można bezpiecznie zignorować.

**Q: Kiedy się martwić?**
A: Gdy widzisz:
- 🔴 Event ID 7, 51 (dysk!)
- 🔴 Event ID 6008, 1001 (niestabilność systemu)
- 🟠 Wiele Event ID 4625 (próby włamania)

**Q: Czy mogę wyłączyć logowanie niektórych zdarzeń?**
A: Tak, ale:
- NIE wyłączaj zdarzeń krytycznych i błędów
- Zdarzenia Security można ograniczyć w Advanced Audit Policy
- Lepiej filtrować podczas analizy niż wyłączać logowanie

---

## 📚 Dodatkowe zasoby

- **Event Viewer** - `eventvwr.msc`
- **Reliability Monitor** - `perfmon /rel`
- **Windows Update** - zawsze aktualne
- **Microsoft Docs** - szczegółowe opisy Event ID

---

*Dokument utworzony przez Windows Event Analyzer*
*Ostatnia aktualizacja: 2025-11-05*
