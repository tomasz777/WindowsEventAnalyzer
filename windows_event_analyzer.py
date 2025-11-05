#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Windows Event Log Analyzer
Analizator dziennika zdarzeń Windows 11
Autor: Claude Code
"""

import win32evtlog
import win32evtlogutil
import win32con
import win32security
from datetime import datetime, timedelta
from collections import defaultdict
from typing import List, Dict, Tuple
import json


class EventSeverity:
    """Klasa definiująca poziomy ważności zdarzeń"""
    CRITICAL = 1
    ERROR = 2
    WARNING = 3
    INFORMATION = 4

    NAMES = {
        1: "KRYTYCZNY",
        2: "BŁĄD",
        3: "OSTRZEŻENIE",
        4: "INFORMACJA"
    }

    # Mapowanie typów zdarzeń Windows na nasze poziomy
    WIN_EVENT_TYPE_MAP = {
        win32con.EVENTLOG_ERROR_TYPE: ERROR,
        win32con.EVENTLOG_WARNING_TYPE: WARNING,
        win32con.EVENTLOG_INFORMATION_TYPE: INFORMATION,
        win32con.EVENTLOG_AUDIT_FAILURE: CRITICAL,
        win32con.EVENTLOG_AUDIT_SUCCESS: INFORMATION
    }


class SolutionDatabase:
    """Baza wiedzy z rozwiązaniami dla popularnych problemów Windows"""

    SOLUTIONS = {
        # Problemy systemowe
        6008: {
            "description": "Nieoczekiwane wyłączenie systemu",
            "severity": EventSeverity.CRITICAL,
            "solutions": [
                "Sprawdź stabilność zasilania (UPS, gniazdko)",
                "Zweryfikuj temperatury CPU i GPU",
                "Sprawdź logi BSOD w Reliability Monitor",
                "Zaktualizuj sterowniki, szczególnie chipset i GPU"
            ]
        },
        1001: {
            "description": "BugCheck - Błąd krytyczny systemu (BSOD)",
            "severity": EventSeverity.CRITICAL,
            "solutions": [
                "Uruchom: sfc /scannow w cmd jako Administrator",
                "Sprawdź pamięć RAM za pomocą Windows Memory Diagnostic",
                "Zaktualizuj wszystkie sterowniki",
                "Sprawdź Event ID dla konkretnego kodu STOP"
            ]
        },
        10016: {
            "description": "Błąd uprawnień DCOM",
            "severity": EventSeverity.WARNING,
            "solutions": [
                "Zazwyczaj można zignorować - to znany problem Windows",
                "Jeśli chcesz naprawić: Component Services -> DCOM Config -> nadaj uprawnienia",
                "Alternatywnie: uruchom PowerShell jako Admin i wykonaj: Get-CimInstance Win32_DCOMApplicationSetting"
            ]
        },
        7000: {
            "description": "Usługa nie uruchomiła się",
            "severity": EventSeverity.ERROR,
            "solutions": [
                "Sprawdź zależności usługi w services.msc",
                "Zweryfikuj typ uruchamiania usługi",
                "Sprawdź uprawnienia konta usługi",
                "Przejrzyj szczegółowe logi aplikacji"
            ]
        },
        7001: {
            "description": "Usługa zależy od innej usługi, która nie uruchomiła się",
            "severity": EventSeverity.ERROR,
            "solutions": [
                "Zidentyfikuj zależną usługę w opisie zdarzenia",
                "Uruchom zależną usługę ręcznie w services.msc",
                "Sprawdź kolejność uruchamiania usług"
            ]
        },
        4625: {
            "description": "Nieudana próba logowania",
            "severity": EventSeverity.WARNING,
            "solutions": [
                "Sprawdź czy to nie próba włamania (wiele prób)",
                "Zweryfikuj poprawność haseł",
                "Sprawdź polityki bezpieczeństwa (secpol.msc)",
                "Rozważ wdrożenie 2FA"
            ]
        },
        4624: {
            "description": "Udane logowanie",
            "severity": EventSeverity.INFORMATION,
            "solutions": [
                "Monitoruj nietypowe logowania",
                "Zweryfikuj logowania w nietypowych godzinach",
                "Sprawdź logowania zdalne (Type 10)"
            ]
        },
        1000: {
            "description": "Awaria aplikacji",
            "severity": EventSeverity.ERROR,
            "solutions": [
                "Zaktualizuj aplikację do najnowszej wersji",
                "Przeinstaluj aplikację",
                "Sprawdź zgodność z Windows 11",
                "Uruchom aplikację jako Administrator",
                "Sprawdź brakujące zależności (.NET, Visual C++ Redistributables)"
            ]
        },
        1002: {
            "description": "Aplikacja przestała odpowiadać",
            "severity": EventSeverity.WARNING,
            "solutions": [
                "Zwiększ zasoby systemowe (RAM, CPU)",
                "Zamknij inne aplikacje",
                "Sprawdź Task Manager pod kątem procesów zużywających zasoby",
                "Zaktualizuj aplikację"
            ]
        },
        # Problemy dyskowe
        7: {
            "description": "Błąd odczytu/zapisu dysku",
            "severity": EventSeverity.CRITICAL,
            "solutions": [
                "PILNE: Wykonaj backup danych!",
                "Uruchom: chkdsk /f /r w cmd jako Administrator",
                "Sprawdź stan dysku: wmic diskdrive get status",
                "Użyj CrystalDiskInfo do sprawdzenia SMART",
                "Rozważ wymianę dysku"
            ]
        },
        51: {
            "description": "Ostrzeżenie o błędzie dysku",
            "severity": EventSeverity.CRITICAL,
            "solutions": [
                "PILNE: Natychmiast wykonaj backup!",
                "Dysk może wkrótce ulec awarii",
                "Sprawdź SMART disk health",
                "Zaplanuj wymianę dysku"
            ]
        },
        # Problemy sieciowe
        5719: {
            "description": "Nie można nawiązać połączenia z kontrolerem domeny",
            "severity": EventSeverity.ERROR,
            "solutions": [
                "Sprawdź połączenie sieciowe",
                "Zweryfikuj ustawienia DNS",
                "Upewnij się że kontroler domeny jest dostępny",
                "Sprawdź firewall"
            ]
        },
        1014: {
            "description": "Błąd rozpoznawania nazw DNS",
            "severity": EventSeverity.WARNING,
            "solutions": [
                "Sprawdź ustawienia DNS w karcie sieciowej",
                "Wypróbuj publiczne DNS (8.8.8.8, 1.1.1.1)",
                "Wyczyść cache DNS: ipconfig /flushdns",
                "Zrestartuj usługę DNS Client"
            ]
        },
        # Dodatkowe problemy aplikacji
        78: {
            "description": "SideBySide - Błąd konfiguracji aplikacji",
            "severity": EventSeverity.WARNING,
            "solutions": [
                "Aplikacja ma konflikt wersji składników (manifests)",
                "Przeinstaluj aplikację",
                "Zainstaluj najnowsze Visual C++ Redistributables",
                "Sprawdź czy aplikacja jest kompatybilna z Windows 11"
            ]
        },
        13: {
            "description": "VSS - Błąd usługi kopiowania woluminów w tle",
            "severity": EventSeverity.WARNING,
            "solutions": [
                "Często występuje podczas wyłączania systemu - można zignorować",
                "Sprawdź czy usługa Volume Shadow Copy działa: services.msc",
                "Uruchom: vssadmin list writers aby sprawdzić status",
                "Jeśli problem się powtarza, zrestartuj usługę VSS"
            ]
        },
        8193: {
            "description": "VSS - Błąd podczas wywoływania CoCreateInstance",
            "severity": EventSeverity.WARNING,
            "solutions": [
                "Związane z zamykaniem systemu - zazwyczaj nieszkodliwe",
                "Upewnij się że usługa VSS jest uruchomiona",
                "Sprawdź czy masz wystarczające uprawnienia",
                "Zrestartuj usługę Volume Shadow Copy"
            ]
        },
        1023: {
            "description": "Perflib - Nie można załadować biblioteki DLL licznika wydajności",
            "severity": EventSeverity.WARNING,
            "solutions": [
                "Biblioteka sysmain.dll może być zablokowana lub uszkodzona",
                "Uruchom: lodctr /R aby przebudować liczniki wydajności",
                "Sprawdź integralność plików: sfc /scannow",
                "Może być spowodowane przez problemy z usługą SysMain"
            ]
        },
        153: {
            "description": "Błąd sterownika karty graficznej (NVIDIA)",
            "severity": EventSeverity.WARNING,
            "solutions": [
                "Zaktualizuj sterowniki NVIDIA do najnowszej wersji",
                "Użyj DDU (Display Driver Uninstaller) i przeinstaluj sterowniki",
                "Sprawdź temperatury GPU",
                "Zweryfikuj zasilanie karty graficznej",
                "Sprawdź czy karta nie jest przetaktowana"
            ]
        },
        10010: {
            "description": "DCOM - Serwer nie zarejestrował się w wymaganym czasie",
            "severity": EventSeverity.WARNING,
            "solutions": [
                "Zazwyczaj nieszkodliwe - typowy problem Windows",
                "Może być związane z RuntimeBroker lub ShellHWDetection",
                "Jeśli chcesz naprawić: Component Services -> DCOM Config",
                "W większości przypadków można bezpiecznie zignorować"
            ]
        },
        1801: {
            "description": "TPM/Secure Boot - Wymagana aktualizacja certyfikatów",
            "severity": EventSeverity.WARNING,
            "solutions": [
                "Windows Update powinien automatycznie zaktualizować certyfikaty",
                "Sprawdź dostępne aktualizacje Windows Update",
                "Może być związane z UEFI/BIOS - sprawdź aktualizacje",
                "To informacyjne - system działa normalnie"
            ]
        },
        # Zdarzenia Security (informacyjne - audyt)
        4672: {
            "description": "Przypisano specjalne uprawnienia do nowego logowania",
            "severity": EventSeverity.INFORMATION,
            "solutions": [
                "To normalne zdarzenie audytu bezpieczeństwa",
                "Pojawia się gdy użytkownik z prawami administratora się loguje",
                "Monitoruj tylko nietypowe wzorce",
                "Brak działania - zdarzenie informacyjne"
            ]
        },
        4798: {
            "description": "Wyliczono członkostwo użytkownika w grupie lokalnej",
            "severity": EventSeverity.INFORMATION,
            "solutions": [
                "Normalne zdarzenie audytu",
                "Rejestruje zapytania o członkostwo w grupach",
                "Brak działania - tylko informacja audytowa",
                "Można wyłączyć w Advanced Audit Policy jeśli nie jest potrzebne"
            ]
        },
        4799: {
            "description": "Wyliczono członkostwo w grupie zabezpieczonej",
            "severity": EventSeverity.INFORMATION,
            "solutions": [
                "Normalne zdarzenie audytu bezpieczeństwa",
                "Występuje podczas sprawdzania uprawnień",
                "Brak działania - tylko monitoring",
                "Przydatne do audytu dostępu"
            ]
        },
        4907: {
            "description": "Zmieniono ustawienia audytu obiektu",
            "severity": EventSeverity.INFORMATION,
            "solutions": [
                "Rejestruje zmiany w ustawieniach audytu plików/folderów",
                "Normalne podczas zmian uprawnień NTFS",
                "Brak działania - zdarzenie informacyjne",
                "Przydatne do śledzenia zmian w polityce bezpieczeństwa"
            ]
        },
        5058: {
            "description": "Operacja na pliku klucza kryptograficznego",
            "severity": EventSeverity.INFORMATION,
            "solutions": [
                "Normalne zdarzenie związane z szyfrowaniem",
                "Występuje podczas operacji na certyfikatach",
                "Brak działania - część audytu kryptografii",
                "Może być związane z Windows Hello, BitLocker lub certyfikatami"
            ]
        },
        5061: {
            "description": "Operacja kryptograficzna",
            "severity": EventSeverity.INFORMATION,
            "solutions": [
                "Standardowe zdarzenie audytu kryptografii",
                "Rejestruje użycie funkcji kryptograficznych",
                "Brak działania - zdarzenie informacyjne",
                "Często związane z CNG (Cryptography Next Generation)"
            ]
        },
        5379: {
            "description": "Odczytano poświadczenia Credential Manager",
            "severity": EventSeverity.INFORMATION,
            "solutions": [
                "Normalne podczas logowania lub używania zapisanych haseł",
                "Rejestruje dostęp do zapisanych poświadczeń",
                "Brak działania - standardowy audyt",
                "Monitoruj tylko nietypowe wzorce dostępu"
            ]
        },
        # Zdarzenia systemowe (informacyjne)
        1: {
            "description": "Usługa Event Log została uruchomiona",
            "severity": EventSeverity.INFORMATION,
            "solutions": [
                "Normalne zdarzenie podczas startu systemu",
                "Oznacza że system dziennika zdarzeń działa poprawnie",
                "Brak działania - zdarzenie informacyjne",
                "To pierwsze zdarzenie zapisywane po starcie systemu"
            ]
        },
        1072: {
            "description": "Użytkownik zainicjował restart lub wyłączenie systemu",
            "severity": EventSeverity.INFORMATION,
            "solutions": [
                "Normalne zdarzenie - planowane wyłączenie/restart",
                "Rejestruje kto i kiedy wyłączył system",
                "Brak działania - tylko informacja",
                "Przydatne do śledzenia aktywności użytkowników"
            ]
        },
        # Zdarzenia Power/Energy
        1074: {
            "description": "System został zamknięty przez użytkownika lub aplikację",
            "severity": EventSeverity.INFORMATION,
            "solutions": [
                "Normalne zamknięcie systemu",
                "Sprawdź powód w szczegółach zdarzenia",
                "Brak działania - zdarzenie informacyjne",
                "Różni się od Event ID 6008 (nieoczekiwane wyłączenie)"
            ]
        },
        # Problemy z usługami
        7040: {
            "description": "Zmieniono typ uruchamiania usługi",
            "severity": EventSeverity.INFORMATION,
            "solutions": [
                "Rejestruje zmiany w konfiguracji usług",
                "Sprawdź czy zmiana była zamierzona",
                "Brak działania jeśli zmiana była zaplanowana",
                "Monitoruj zmiany w krytycznych usługach"
            ]
        }
    }

    @classmethod
    def get_solution(cls, event_id: int) -> Dict:
        """Pobiera rozwiązanie dla danego Event ID"""
        if event_id in cls.SOLUTIONS:
            return cls.SOLUTIONS[event_id]
        return {
            "description": "Nieznany problem",
            "severity": EventSeverity.WARNING,
            "solutions": [
                "Wyszukaj Event ID w Google: 'Windows Event ID {}'".format(event_id),
                "Sprawdź szczegóły w Event Viewer",
                "Przejrzyj dokumentację Microsoft",
                "Rozważ utworzenie wątku na forum Microsoft Community"
            ]
        }


class WindowsEventAnalyzer:
    """Główna klasa analizatora dziennika zdarzeń Windows"""

    def __init__(self, hours_back: int = 24):
        """
        Inicjalizacja analizatora

        Args:
            hours_back: Ile godzin wstecz analizować (domyślnie 24h)
        """
        self.hours_back = hours_back
        self.logs_to_check = ['System', 'Application', 'Security']
        self.events = []

    def read_event_log(self, log_name: str) -> List[Dict]:
        """
        Odczytuje zdarzenia z określonego dziennika

        Args:
            log_name: Nazwa dziennika (System, Application, Security)

        Returns:
            Lista zdarzeń jako słowniki
        """
        events = []
        try:
            hand = win32evtlog.OpenEventLog(None, log_name)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

            # Oblicz czas od którego czytamy
            time_threshold = datetime.now() - timedelta(hours=self.hours_back)

            while True:
                event_records = win32evtlog.ReadEventLog(hand, flags, 0)
                if not event_records:
                    break

                for event in event_records:
                    # Konwertuj czas zdarzenia
                    try:
                        event_time = datetime.strptime(str(event.TimeGenerated), '%Y-%m-%d %H:%M:%S')
                    except:
                        event_time = datetime.now()

                    # Sprawdź czy zdarzenie jest w zakresie czasowym
                    if event_time < time_threshold:
                        win32evtlog.CloseEventLog(hand)
                        return events

                    # Mapuj typ zdarzenia na nasze poziomy ważności
                    severity = EventSeverity.WIN_EVENT_TYPE_MAP.get(
                        event.EventType,
                        EventSeverity.INFORMATION
                    )

                    # Pobierz tekst zdarzenia
                    try:
                        event_message = win32evtlogutil.SafeFormatMessage(event, log_name)
                    except:
                        event_message = "Brak opisu zdarzenia"

                    # Pobierz źródło zdarzenia
                    source_name = str(event.SourceName) if event.SourceName else "Unknown"

                    event_data = {
                        'log_name': log_name,
                        'event_id': event.EventID & 0xFFFF,  # Usuń górne bity
                        'source': source_name,
                        'time': event_time,
                        'severity': severity,
                        'severity_name': EventSeverity.NAMES[severity],
                        'message': event_message[:500],  # Ogranicz długość
                        'category': event.EventCategory
                    }

                    events.append(event_data)

            win32evtlog.CloseEventLog(hand)

        except Exception as e:
            print(f"Błąd podczas odczytu dziennika {log_name}: {str(e)}")

        return events

    def analyze_events(self):
        """Analizuje wszystkie skonfigurowane dzienniki"""
        print(f"Analizuję dzienniki zdarzeń z ostatnich {self.hours_back} godzin...\n")

        for log_name in self.logs_to_check:
            print(f"Czytam dziennik: {log_name}...")
            log_events = self.read_event_log(log_name)
            self.events.extend(log_events)
            print(f"  Znaleziono {len(log_events)} zdarzeń\n")

        # Sortuj zdarzenia według ważności i czasu
        self.events.sort(key=lambda x: (x['severity'], x['time']), reverse=True)

    def generate_report(self) -> str:
        """
        Generuje szczegółowy raport z analizy

        Returns:
            Sformatowany raport tekstowy
        """
        if not self.events:
            return "Brak zdarzeń do analizy."

        # Statystyki
        total_events = len(self.events)
        severity_counts = defaultdict(int)
        event_id_counts = defaultdict(int)
        source_counts = defaultdict(int)

        for event in self.events:
            severity_counts[event['severity']] += 1
            event_id_counts[event['event_id']] += 1
            source_counts[event['source']] += 1

        # Generuj raport
        report_lines = []
        report_lines.append("=" * 80)
        report_lines.append("RAPORT ANALIZY DZIENNIKA ZDARZEŃ WINDOWS 11")
        report_lines.append("=" * 80)
        report_lines.append(f"Data wygenerowania: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append(f"Okres analizy: Ostatnie {self.hours_back} godzin")
        report_lines.append(f"Analizowane dzienniki: {', '.join(self.logs_to_check)}")
        report_lines.append("")

        # Podsumowanie statystyk
        report_lines.append("-" * 80)
        report_lines.append("PODSUMOWANIE STATYSTYK")
        report_lines.append("-" * 80)
        report_lines.append(f"Łączna liczba zdarzeń: {total_events}")
        report_lines.append("")
        report_lines.append("Podział według ważności:")
        for severity in sorted(severity_counts.keys()):
            count = severity_counts[severity]
            percentage = (count / total_events) * 100
            name = EventSeverity.NAMES[severity]
            report_lines.append(f"  {name:15} : {count:6} ({percentage:5.1f}%)")
        report_lines.append("")

        # Najczęstsze Event ID
        report_lines.append("-" * 80)
        report_lines.append("TOP 10 NAJCZĘSTSZYCH ZDARZEŃ (Event ID)")
        report_lines.append("-" * 80)
        top_event_ids = sorted(event_id_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        for event_id, count in top_event_ids:
            solution_info = SolutionDatabase.get_solution(event_id)
            report_lines.append(f"Event ID {event_id:5} : {count:4} wystąpień - {solution_info['description']}")
        report_lines.append("")

        # Szczegółowa analiza zdarzeń krytycznych i błędów
        critical_and_errors = [e for e in self.events if e['severity'] <= EventSeverity.ERROR]

        if critical_and_errors:
            report_lines.append("-" * 80)
            report_lines.append(f"SZCZEGÓŁOWA ANALIZA - ZDARZENIA KRYTYCZNE I BŁĘDY ({len(critical_and_errors)})")
            report_lines.append("-" * 80)
            report_lines.append("")

            # Grupuj według Event ID
            grouped_events = defaultdict(list)
            for event in critical_and_errors:
                grouped_events[event['event_id']].append(event)

            for event_id, event_list in sorted(grouped_events.items(), key=lambda x: len(x[1]), reverse=True):
                solution_info = SolutionDatabase.get_solution(event_id)
                first_event = event_list[0]

                report_lines.append("=" * 80)
                report_lines.append(f"Event ID: {event_id}")
                report_lines.append(f"Ważność: {first_event['severity_name']}")
                report_lines.append(f"Liczba wystąpień: {len(event_list)}")
                report_lines.append(f"Źródło: {first_event['source']}")
                report_lines.append(f"Dziennik: {first_event['log_name']}")
                report_lines.append(f"Ostatnie wystąpienie: {event_list[0]['time'].strftime('%Y-%m-%d %H:%M:%S')}")
                report_lines.append("")
                report_lines.append(f"Opis problemu:")
                report_lines.append(f"  {solution_info['description']}")
                report_lines.append("")
                report_lines.append("Zalecane rozwiązania:")
                for i, solution in enumerate(solution_info['solutions'], 1):
                    report_lines.append(f"  {i}. {solution}")
                report_lines.append("")
                report_lines.append(f"Przykładowa wiadomość zdarzenia:")
                report_lines.append(f"  {first_event['message'][:300]}...")
                report_lines.append("")

        # Ostrzeżenia
        warnings = [e for e in self.events if e['severity'] == EventSeverity.WARNING]
        if warnings:
            report_lines.append("-" * 80)
            report_lines.append(f"PODSUMOWANIE OSTRZEŻEŃ ({len(warnings)})")
            report_lines.append("-" * 80)

            warning_groups = defaultdict(int)
            for event in warnings:
                warning_groups[event['event_id']] += 1

            for event_id, count in sorted(warning_groups.items(), key=lambda x: x[1], reverse=True)[:15]:
                solution_info = SolutionDatabase.get_solution(event_id)
                report_lines.append(f"  Event ID {event_id:5} ({count:3}x) : {solution_info['description']}")
            report_lines.append("")

        # Rekomendacje końcowe
        report_lines.append("-" * 80)
        report_lines.append("REKOMENDACJE KOŃCOWE")
        report_lines.append("-" * 80)

        recommendations = []

        critical_count = severity_counts.get(EventSeverity.CRITICAL, 0)
        error_count = severity_counts.get(EventSeverity.ERROR, 0)

        if critical_count > 0:
            recommendations.append(
                f"[!] PILNE: Wykryto {critical_count} zdarzeń krytycznych! "
                "Należy natychmiast przejrzeć i rozwiązać te problemy."
            )

        if error_count > 10:
            recommendations.append(
                f"[!] Wysoka liczba błędów ({error_count}). "
                "Zalecane jest przeprowadzenie konserwacji systemu."
            )

        if 6008 in event_id_counts:
            recommendations.append(
                "[!] Wykryto nieoczekiwane wyłączenia systemu. "
                "Sprawdź stabilność zasilania i temperatury komponentów."
            )

        if 7 in event_id_counts or 51 in event_id_counts:
            recommendations.append(
                "[!] UWAGA: Wykryto problemy z dyskiem! "
                "NATYCHMIAST wykonaj backup danych i sprawdź stan dysku!"
            )

        if 4625 in event_id_counts and event_id_counts[4625] > 5:
            recommendations.append(
                f"[!] Wykryto {event_id_counts[4625]} nieudanych prób logowania. "
                "Sprawdź logi bezpieczeństwa pod kątem potencjalnych prób włamania."
            )

        if not recommendations:
            recommendations.append(
                "[OK] System działa stabilnie. Nie wykryto poważnych problemów wymagających natychmiastowej interwencji."
            )

        for rec in recommendations:
            report_lines.append(f"  {rec}")
            report_lines.append("")

        # Ogólne zalecenia
        report_lines.append("Ogólne zalecenia konserwacyjne:")
        report_lines.append("  1. Regularnie aktualizuj Windows Update")
        report_lines.append("  2. Utrzymuj aktualne sterowniki urządzeń")
        report_lines.append("  3. Wykonuj regularne backupy danych")
        report_lines.append("  4. Monitoruj temperatury komponentów")
        report_lines.append("  5. Czyść pliki tymczasowe (Disk Cleanup)")
        report_lines.append("")

        report_lines.append("=" * 80)
        report_lines.append("KONIEC RAPORTU")
        report_lines.append("=" * 80)

        return "\n".join(report_lines)

    def generate_html_report(self) -> str:
        """
        Generuje szczegółowy raport w formacie HTML

        Returns:
            Sformatowany raport HTML
        """
        if not self.events:
            return "<html><body><h1>Brak zdarzeń do analizy.</h1></body></html>"

        # Statystyki
        total_events = len(self.events)
        severity_counts = defaultdict(int)
        event_id_counts = defaultdict(int)
        source_counts = defaultdict(int)

        for event in self.events:
            severity_counts[event['severity']] += 1
            event_id_counts[event['event_id']] += 1
            source_counts[event['source']] += 1

        # Kolory dla poziomów ważności
        severity_colors = {
            EventSeverity.CRITICAL: '#dc3545',  # Czerwony
            EventSeverity.ERROR: '#fd7e14',     # Pomarańczowy
            EventSeverity.WARNING: '#ffc107',   # Żółty
            EventSeverity.INFORMATION: '#28a745' # Zielony
        }

        # Generuj HTML
        html = []
        html.append("""<!DOCTYPE html>
<html lang="pl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Raport Analizy Dziennika Zdarzeń Windows 11</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            line-height: 1.6;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }

        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }

        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }

        .header .meta {
            opacity: 0.9;
            font-size: 1.1em;
        }

        .content {
            padding: 30px;
        }

        .section {
            margin-bottom: 40px;
        }

        .section-title {
            font-size: 1.8em;
            color: #333;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #667eea;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .stat-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }

        .stat-card .number {
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }

        .stat-card .label {
            font-size: 1em;
            opacity: 0.9;
        }

        .severity-breakdown {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }

        .severity-item {
            display: flex;
            align-items: center;
            margin-bottom: 15px;
            padding: 10px;
            background: white;
            border-radius: 5px;
            border-left: 4px solid;
        }

        .severity-label {
            flex: 0 0 150px;
            font-weight: bold;
        }

        .severity-bar {
            flex: 1;
            height: 30px;
            background: #e9ecef;
            border-radius: 15px;
            overflow: hidden;
            margin: 0 15px;
        }

        .severity-fill {
            height: 100%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
            transition: width 0.5s ease;
        }

        .severity-count {
            flex: 0 0 100px;
            text-align: right;
            font-weight: bold;
        }

        .event-table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        .event-table th {
            background: #667eea;
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
        }

        .event-table td {
            padding: 12px 15px;
            border-bottom: 1px solid #e9ecef;
        }

        .event-table tr:last-child td {
            border-bottom: none;
        }

        .event-table tr:hover {
            background: #f8f9fa;
        }

        .event-card {
            background: white;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            border-left: 5px solid;
        }

        .event-card.critical {
            border-left-color: #dc3545;
        }

        .event-card.error {
            border-left-color: #fd7e14;
        }

        .event-card.warning {
            border-left-color: #ffc107;
        }

        .event-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            padding-bottom: 15px;
            border-bottom: 2px solid #e9ecef;
        }

        .event-id {
            font-size: 1.5em;
            font-weight: bold;
            color: #333;
        }

        .event-badge {
            padding: 5px 15px;
            border-radius: 20px;
            color: white;
            font-weight: bold;
            font-size: 0.9em;
        }

        .event-info {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 15px;
        }

        .info-item {
            display: flex;
            flex-direction: column;
        }

        .info-label {
            font-size: 0.85em;
            color: #6c757d;
            margin-bottom: 5px;
        }

        .info-value {
            font-weight: 600;
            color: #333;
        }

        .problem-description {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 15px;
        }

        .solutions {
            margin-top: 15px;
        }

        .solutions-title {
            font-weight: bold;
            color: #667eea;
            margin-bottom: 10px;
            font-size: 1.1em;
        }

        .solutions ol {
            margin-left: 20px;
        }

        .solutions li {
            margin-bottom: 8px;
            color: #333;
        }

        .recommendations {
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            color: white;
            padding: 25px;
            border-radius: 8px;
            margin-top: 30px;
        }

        .recommendations h3 {
            margin-bottom: 15px;
            font-size: 1.5em;
        }

        .recommendations ul {
            list-style: none;
        }

        .recommendations li {
            padding: 10px 0;
            padding-left: 25px;
            position: relative;
        }

        .recommendations li:before {
            content: "⚠";
            position: absolute;
            left: 0;
            font-size: 1.2em;
        }

        .recommendations.success {
            background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
        }

        .recommendations.success li:before {
            content: "✓";
        }

        .footer {
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #6c757d;
            margin-top: 30px;
        }

        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: bold;
        }

        @media print {
            body {
                background: white;
                padding: 0;
            }
            .container {
                box-shadow: none;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🖥️ Raport Analizy Dziennika Zdarzeń Windows 11</h1>
            <div class="meta">""")

        html.append(f"""
                <p>Data wygenerowania: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>Okres analizy: Ostatnie {self.hours_back} godzin</p>
                <p>Analizowane dzienniki: {', '.join(self.logs_to_check)}</p>
            </div>
        </div>

        <div class="content">""")

        # Statystyki główne
        html.append("""
            <div class="section">
                <h2 class="section-title">📊 Podsumowanie Statystyk</h2>
                <div class="stats-grid">""")

        html.append(f"""
                    <div class="stat-card">
                        <div class="number">{total_events:,}</div>
                        <div class="label">Łączna liczba zdarzeń</div>
                    </div>""")

        for severity in sorted(severity_counts.keys()):
            count = severity_counts[severity]
            name = EventSeverity.NAMES[severity]
            html.append(f"""
                    <div class="stat-card">
                        <div class="number">{count:,}</div>
                        <div class="label">{name}</div>
                    </div>""")

        html.append("""
                </div>""")

        # Podział według ważności
        html.append("""
                <div class="severity-breakdown">
                    <h3 style="margin-bottom: 20px;">Podział według ważności:</h3>""")

        for severity in sorted(severity_counts.keys()):
            count = severity_counts[severity]
            percentage = (count / total_events) * 100
            name = EventSeverity.NAMES[severity]
            color = severity_colors[severity]

            html.append(f"""
                    <div class="severity-item" style="border-left-color: {color};">
                        <div class="severity-label">{name}</div>
                        <div class="severity-bar">
                            <div class="severity-fill" style="width: {percentage}%; background-color: {color};">
                                {percentage:.1f}%
                            </div>
                        </div>
                        <div class="severity-count">{count:,} zdarzeń</div>
                    </div>""")

        html.append("""
                </div>
            </div>""")

        # Top 10 Event ID
        html.append("""
            <div class="section">
                <h2 class="section-title">🔝 Top 10 Najczęstszych Zdarzeń</h2>
                <table class="event-table">
                    <thead>
                        <tr>
                            <th>Event ID</th>
                            <th>Liczba wystąpień</th>
                            <th>Opis</th>
                        </tr>
                    </thead>
                    <tbody>""")

        top_event_ids = sorted(event_id_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        for event_id, count in top_event_ids:
            solution_info = SolutionDatabase.get_solution(event_id)
            html.append(f"""
                        <tr>
                            <td><strong>{event_id}</strong></td>
                            <td>{count:,}</td>
                            <td>{solution_info['description']}</td>
                        </tr>""")

        html.append("""
                    </tbody>
                </table>
            </div>""")

        # Szczegółowa analiza błędów krytycznych
        critical_and_errors = [e for e in self.events if e['severity'] <= EventSeverity.ERROR]

        if critical_and_errors:
            html.append(f"""
            <div class="section">
                <h2 class="section-title">🚨 Szczegółowa Analiza - Zdarzenia Krytyczne i Błędy ({len(critical_and_errors)})</h2>""")

            # Grupuj według Event ID
            grouped_events = defaultdict(list)
            for event in critical_and_errors:
                grouped_events[event['event_id']].append(event)

            for event_id, event_list in sorted(grouped_events.items(), key=lambda x: len(x[1]), reverse=True):
                solution_info = SolutionDatabase.get_solution(event_id)
                first_event = event_list[0]

                severity_class = 'critical' if first_event['severity'] == EventSeverity.CRITICAL else 'error'
                severity_color = severity_colors[first_event['severity']]

                html.append(f"""
                <div class="event-card {severity_class}">
                    <div class="event-header">
                        <div class="event-id">Event ID: {event_id}</div>
                        <div class="event-badge" style="background-color: {severity_color};">
                            {first_event['severity_name']}
                        </div>
                    </div>

                    <div class="event-info">
                        <div class="info-item">
                            <div class="info-label">Liczba wystąpień</div>
                            <div class="info-value">{len(event_list)}</div>
                        </div>
                        <div class="info-item">
                            <div class="info-label">Źródło</div>
                            <div class="info-value">{first_event['source']}</div>
                        </div>
                        <div class="info-item">
                            <div class="info-label">Dziennik</div>
                            <div class="info-value">{first_event['log_name']}</div>
                        </div>
                        <div class="info-item">
                            <div class="info-label">Ostatnie wystąpienie</div>
                            <div class="info-value">{event_list[0]['time'].strftime('%Y-%m-%d %H:%M:%S')}</div>
                        </div>
                    </div>

                    <div class="problem-description">
                        <strong>Opis problemu:</strong><br>
                        {solution_info['description']}
                    </div>

                    <div class="solutions">
                        <div class="solutions-title">💡 Zalecane rozwiązania:</div>
                        <ol>""")

                for solution in solution_info['solutions']:
                    html.append(f"<li>{solution}</li>")

                html.append(f"""
                        </ol>
                    </div>

                    <details style="margin-top: 15px;">
                        <summary style="cursor: pointer; color: #667eea; font-weight: bold;">
                            Przykładowa wiadomość zdarzenia
                        </summary>
                        <div style="margin-top: 10px; padding: 10px; background: #f8f9fa; border-radius: 5px; font-family: monospace; font-size: 0.9em;">
                            {first_event['message'][:500]}...
                        </div>
                    </details>
                </div>""")

            html.append("</div>")

        # Ostrzeżenia
        warnings = [e for e in self.events if e['severity'] == EventSeverity.WARNING]
        if warnings:
            html.append(f"""
            <div class="section">
                <h2 class="section-title">⚠️ Podsumowanie Ostrzeżeń ({len(warnings)})</h2>
                <table class="event-table">
                    <thead>
                        <tr>
                            <th>Event ID</th>
                            <th>Wystąpienia</th>
                            <th>Opis</th>
                        </tr>
                    </thead>
                    <tbody>""")

            warning_groups = defaultdict(int)
            for event in warnings:
                warning_groups[event['event_id']] += 1

            for event_id, count in sorted(warning_groups.items(), key=lambda x: x[1], reverse=True)[:15]:
                solution_info = SolutionDatabase.get_solution(event_id)
                html.append(f"""
                        <tr>
                            <td><strong>{event_id}</strong></td>
                            <td>{count}</td>
                            <td>{solution_info['description']}</td>
                        </tr>""")

            html.append("""
                    </tbody>
                </table>
            </div>""")

        # Rekomendacje końcowe
        recommendations = []
        critical_count = severity_counts.get(EventSeverity.CRITICAL, 0)
        error_count = severity_counts.get(EventSeverity.ERROR, 0)

        if critical_count > 0:
            recommendations.append(
                f"PILNE: Wykryto {critical_count} zdarzeń krytycznych! "
                "Należy natychmiast przejrzeć i rozwiązać te problemy."
            )

        if error_count > 10:
            recommendations.append(
                f"Wysoka liczba błędów ({error_count}). "
                "Zalecane jest przeprowadzenie konserwacji systemu."
            )

        if 6008 in event_id_counts:
            recommendations.append(
                "Wykryto nieoczekiwane wyłączenia systemu. "
                "Sprawdź stabilność zasilania i temperatury komponentów."
            )

        if 7 in event_id_counts or 51 in event_id_counts:
            recommendations.append(
                "UWAGA: Wykryto problemy z dyskiem! "
                "NATYCHMIAST wykonaj backup danych i sprawdź stan dysku!"
            )

        if 4625 in event_id_counts and event_id_counts[4625] > 5:
            recommendations.append(
                f"Wykryto {event_id_counts[4625]} nieudanych prób logowania. "
                "Sprawdź logi bezpieczeństwa pod kątem potencjalnych prób włamania."
            )

        rec_class = "success" if not recommendations else ""
        html.append(f"""
            <div class="recommendations {rec_class}">
                <h3>📋 Rekomendacje Końcowe</h3>
                <ul>""")

        if recommendations:
            for rec in recommendations:
                html.append(f"<li>{rec}</li>")
        else:
            html.append("<li>System działa stabilnie. Nie wykryto poważnych problemów wymagających natychmiastowej interwencji.</li>")

        html.append("""
                </ul>

                <h4 style="margin-top: 20px; margin-bottom: 10px;">Ogólne zalecenia konserwacyjne:</h4>
                <ul>
                    <li>Regularnie aktualizuj Windows Update</li>
                    <li>Utrzymuj aktualne sterowniki urządzeń</li>
                    <li>Wykonuj regularne backupy danych</li>
                    <li>Monitoruj temperatury komponentów</li>
                    <li>Czyść pliki tymczasowe (Disk Cleanup)</li>
                </ul>
            </div>
        </div>

        <div class="footer">
            <p>Raport wygenerowany przez <strong>Windows Event Analyzer</strong></p>
            <p>© 2025 Claude Code - Analizator Dziennika Zdarzeń Windows 11</p>
        </div>
    </div>
</body>
</html>""")

        return "\n".join(html)

    def save_report(self, filename: str = None, format: str = 'txt'):
        """
        Zapisuje raport do pliku

        Args:
            filename: Nazwa pliku (jeśli None, generuje automatycznie)
            format: Format raportu - 'txt' lub 'html' (domyślnie 'txt')
        """
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            extension = 'html' if format == 'html' else 'txt'
            filename = f"event_log_report_{timestamp}.{extension}"

        # Wybierz odpowiedni generator
        if format == 'html':
            report = self.generate_html_report()
        else:
            report = self.generate_report()

        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(report)
            print(f"\nRaport zapisany do pliku: {filename}")

            # Jeśli HTML, pokaż informację o otwieraniu w przeglądarce
            if format == 'html':
                print(f"Otwórz plik w przeglądarce aby zobaczyć raport.")
                import os
                abs_path = os.path.abspath(filename)
                print(f"Pełna ścieżka: {abs_path}")

            return filename
        except Exception as e:
            print(f"Błąd podczas zapisu raportu: {str(e)}")
            return None


def main():
    """Główna funkcja programu"""
    # Ustaw kodowanie konsoli dla Windows
    import sys
    if sys.platform == 'win32':
        try:
            import os
            os.system('chcp 65001 >nul 2>&1')
            sys.stdout.reconfigure(encoding='utf-8')
        except:
            pass

    print("=" * 80)
    print("ANALIZATOR DZIENNIKA ZDARZEŃ WINDOWS 11")
    print("=" * 80)
    print()

    # Pytaj użytkownika o zakres czasowy
    print("Wybierz zakres czasowy analizy:")
    print("1. Ostatnie 24 godziny (domyślnie)")
    print("2. Ostatnie 48 godzin")
    print("3. Ostatnie 7 dni")
    print("4. Własny zakres")
    print()

    choice = input("Wybór (1-4) [1]: ").strip() or "1"

    hours_map = {
        "1": 24,
        "2": 48,
        "3": 168,  # 7 dni
    }

    if choice in hours_map:
        hours_back = hours_map[choice]
    elif choice == "4":
        try:
            hours_back = int(input("Podaj liczbę godzin wstecz: "))
        except ValueError:
            print("Nieprawidłowa wartość, używam domyślnych 24 godzin.")
            hours_back = 24
    else:
        print("Nieprawidłowy wybór, używam domyślnych 24 godzin.")
        hours_back = 24

    print()
    print(f"Rozpoczynam analizę ostatnich {hours_back} godzin...")
    print("To może potrwać kilka minut w zależności od liczby zdarzeń...")
    print()

    # Utwórz analizator i przeprowadź analizę
    analyzer = WindowsEventAnalyzer(hours_back=hours_back)
    analyzer.analyze_events()

    # Wyświetl raport tekstowy w konsoli
    report = analyzer.generate_report()
    print(report)

    # Zapytaj czy zapisać raport
    print()
    save_choice = input("Czy zapisać raport do pliku? (t/n) [t]: ").strip().lower() or "t"

    if save_choice in ['t', 'tak', 'y', 'yes']:
        print()
        print("Wybierz format raportu:")
        print("1. TXT - Format tekstowy (domyślnie)")
        print("2. HTML - Format HTML z graficzną prezentacją")
        print("3. Oba formaty")
        print()

        format_choice = input("Wybór (1-3) [1]: ").strip() or "1"

        if format_choice == "2":
            analyzer.save_report(format='html')
        elif format_choice == "3":
            print("\nZapisuję raport w formacie TXT...")
            analyzer.save_report(format='txt')
            print("\nZapisuję raport w formacie HTML...")
            analyzer.save_report(format='html')
        else:
            analyzer.save_report(format='txt')

    print()
    print("Analiza zakończona!")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nPrzerwano przez użytkownika.")
    except Exception as e:
        print(f"\n\nWystąpił błąd: {str(e)}")
        print("Upewnij się, że uruchamiasz skrypt jako Administrator!")
