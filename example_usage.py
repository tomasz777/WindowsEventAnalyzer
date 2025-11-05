#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Przykłady użycia Windows Event Analyzer
Demonstracja różnych sposobów wykorzystania analizatora
"""

from windows_event_analyzer import (
    WindowsEventAnalyzer,
    EventSeverity,
    SolutionDatabase
)
from datetime import datetime


def example_basic_analysis():
    """Przykład 1: Podstawowa analiza z domyślnymi ustawieniami"""
    print("=" * 80)
    print("PRZYKŁAD 1: Podstawowa analiza (ostatnie 24 godziny)")
    print("=" * 80)

    analyzer = WindowsEventAnalyzer(hours_back=24)
    analyzer.analyze_events()

    # Wyświetl tylko podsumowanie
    print(f"\nZnaleziono łącznie: {len(analyzer.events)} zdarzeń")

    # Policz według ważności
    critical = sum(1 for e in analyzer.events if e['severity'] == EventSeverity.CRITICAL)
    errors = sum(1 for e in analyzer.events if e['severity'] == EventSeverity.ERROR)
    warnings = sum(1 for e in analyzer.events if e['severity'] == EventSeverity.WARNING)

    print(f"Zdarzenia krytyczne: {critical}")
    print(f"Błędy: {errors}")
    print(f"Ostrzeżenia: {warnings}")

    # Zapisz raport
    analyzer.save_report("raport_podstawowy.txt")


def example_custom_time_range():
    """Przykład 2: Analiza z niestandardowym zakresem czasowym"""
    print("\n" + "=" * 80)
    print("PRZYKŁAD 2: Analiza ostatnich 7 dni")
    print("=" * 80)

    analyzer = WindowsEventAnalyzer(hours_back=168)  # 7 dni = 168 godzin
    analyzer.analyze_events()

    print(f"\nZnaleziono {len(analyzer.events)} zdarzeń z ostatnich 7 dni")
    analyzer.save_report("raport_tygodniowy.txt")


def example_critical_errors_only():
    """Przykład 3: Analiza tylko zdarzeń krytycznych i błędów"""
    print("\n" + "=" * 80)
    print("PRZYKŁAD 3: Filtrowanie tylko krytycznych zdarzeń i błędów")
    print("=" * 80)

    analyzer = WindowsEventAnalyzer(hours_back=48)
    analyzer.analyze_events()

    # Filtruj tylko krytyczne i błędy
    critical_and_errors = [
        e for e in analyzer.events
        if e['severity'] <= EventSeverity.ERROR
    ]

    print(f"\nZnaleziono {len(critical_and_errors)} zdarzeń krytycznych/błędów")

    # Wyświetl szczegóły
    for event in critical_and_errors[:5]:  # Pierwszych 5
        print(f"\n- Event ID: {event['event_id']}")
        print(f"  Ważność: {event['severity_name']}")
        print(f"  Źródło: {event['source']}")
        print(f"  Czas: {event['time']}")
        print(f"  Wiadomość: {event['message'][:100]}...")


def example_specific_event_id():
    """Przykład 4: Wyszukiwanie konkretnego Event ID"""
    print("\n" + "=" * 80)
    print("PRZYKŁAD 4: Wyszukiwanie konkretnego Event ID")
    print("=" * 80)

    analyzer = WindowsEventAnalyzer(hours_back=24)
    analyzer.analyze_events()

    # Szukaj konkretnego Event ID (np. 10016 - błąd DCOM)
    target_event_id = 10016
    matching_events = [e for e in analyzer.events if e['event_id'] == target_event_id]

    print(f"\nZnaleziono {len(matching_events)} wystąpień Event ID {target_event_id}")

    if matching_events:
        # Pobierz rozwiązanie z bazy
        solution = SolutionDatabase.get_solution(target_event_id)
        print(f"\nOpis: {solution['description']}")
        print("\nZalecane rozwiązania:")
        for i, sol in enumerate(solution['solutions'], 1):
            print(f"{i}. {sol}")


def example_statistics():
    """Przykład 5: Generowanie statystyk"""
    print("\n" + "=" * 80)
    print("PRZYKŁAD 5: Zaawansowane statystyki")
    print("=" * 80)

    analyzer = WindowsEventAnalyzer(hours_back=24)
    analyzer.analyze_events()

    # Statystyki według dzienników
    from collections import defaultdict

    log_stats = defaultdict(lambda: {'total': 0, 'errors': 0, 'critical': 0})

    for event in analyzer.events:
        log_name = event['log_name']
        log_stats[log_name]['total'] += 1

        if event['severity'] == EventSeverity.ERROR:
            log_stats[log_name]['errors'] += 1
        elif event['severity'] == EventSeverity.CRITICAL:
            log_stats[log_name]['critical'] += 1

    print("\nStatystyki według dzienników:")
    for log_name, stats in log_stats.items():
        print(f"\n{log_name}:")
        print(f"  Łącznie: {stats['total']}")
        print(f"  Błędy: {stats['errors']}")
        print(f"  Krytyczne: {stats['critical']}")

    # Top 5 najbardziej problematycznych źródeł
    source_errors = defaultdict(int)
    for event in analyzer.events:
        if event['severity'] <= EventSeverity.ERROR:
            source_errors[event['source']] += 1

    print("\n\nTop 5 źródeł z największą liczbą błędów:")
    for source, count in sorted(source_errors.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"  {source}: {count} błędów")


def example_hourly_breakdown():
    """Przykład 6: Rozkład zdarzeń według godzin"""
    print("\n" + "=" * 80)
    print("PRZYKŁAD 6: Analiza rozkładu zdarzeń w czasie")
    print("=" * 80)

    analyzer = WindowsEventAnalyzer(hours_back=24)
    analyzer.analyze_events()

    # Grupuj według godzin
    from collections import defaultdict
    hourly_counts = defaultdict(int)

    for event in analyzer.events:
        if event['severity'] <= EventSeverity.ERROR:  # Tylko błędy i krytyczne
            hour = event['time'].hour
            hourly_counts[hour] += 1

    print("\nRozkład błędów i zdarzeń krytycznych według godzin (ostatnie 24h):")
    for hour in sorted(hourly_counts.keys()):
        bar = "█" * (hourly_counts[hour] // 5 or 1)  # Prosty wykres
        print(f"{hour:02d}:00 | {bar} ({hourly_counts[hour]})")


def example_security_audit():
    """Przykład 7: Audit bezpieczeństwa"""
    print("\n" + "=" * 80)
    print("PRZYKŁAD 7: Audit bezpieczeństwa")
    print("=" * 80)

    analyzer = WindowsEventAnalyzer(hours_back=24)
    analyzer.analyze_events()

    # Szukaj zdarzeń związanych z bezpieczeństwem
    security_events = [e for e in analyzer.events if e['log_name'] == 'Security']

    # Nieudane logowania
    failed_logins = [e for e in security_events if e['event_id'] == 4625]
    successful_logins = [e for e in security_events if e['event_id'] == 4624]

    print(f"\nZdarzenia bezpieczeństwa (ostatnie 24h):")
    print(f"Łącznie zdarzeń Security: {len(security_events)}")
    print(f"Udane logowania: {len(successful_logins)}")
    print(f"Nieudane próby logowania: {len(failed_logins)}")

    if len(failed_logins) > 10:
        print(f"\n[!] UWAGA: Wykryto {len(failed_logins)} nieudanych prób logowania!")
        print("To może wskazywać na próby włamania. Zalecane działania:")
        solution = SolutionDatabase.get_solution(4625)
        for sol in solution['solutions']:
            print(f"  - {sol}")


def example_disk_health_check():
    """Przykład 8: Sprawdzanie zdrowia dysku"""
    print("\n" + "=" * 80)
    print("PRZYKŁAD 8: Sprawdzanie zdrowia dysku")
    print("=" * 80)

    analyzer = WindowsEventAnalyzer(hours_back=168)  # 7 dni
    analyzer.analyze_events()

    # Szukaj problemów dyskowych
    disk_errors = [
        e for e in analyzer.events
        if e['event_id'] in [7, 51, 153, 154]  # Znane Event ID błędów dysku
    ]

    print(f"\nSprawdzanie błędów dyskowych (ostatnie 7 dni):")
    print(f"Znaleziono: {len(disk_errors)} potencjalnych problemów")

    if disk_errors:
        print("\n[!] UWAGA: Wykryto problemy z dyskiem!")
        print("NATYCHMIAST wykonaj backup danych!")
        print("\nSzczegóły:")
        for event in disk_errors[:10]:  # Pierwszych 10
            print(f"\n  Event ID {event['event_id']}: {event['time']}")
            print(f"  Źródło: {event['source']}")
            solution = SolutionDatabase.get_solution(event['event_id'])
            print(f"  Problem: {solution['description']}")
    else:
        print("[OK] Nie wykryto problemów z dyskiem")


def example_custom_report():
    """Przykład 9: Tworzenie niestandardowego raportu"""
    print("\n" + "=" * 80)
    print("PRZYKŁAD 9: Niestandardowy raport")
    print("=" * 80)

    analyzer = WindowsEventAnalyzer(hours_back=24)
    analyzer.analyze_events()

    # Stwórz własny format raportu
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    custom_report = []
    custom_report.append("NIESTANDARDOWY RAPORT ZDARZEŃ")
    custom_report.append(f"Wygenerowano: {timestamp}")
    custom_report.append("=" * 60)
    custom_report.append("")

    # Dodaj tylko najważniejsze informacje
    critical_events = [e for e in analyzer.events if e['severity'] == EventSeverity.CRITICAL]

    custom_report.append(f"ZDARZENIA KRYTYCZNE: {len(critical_events)}")
    if critical_events:
        custom_report.append("")
        for event in critical_events[:10]:
            custom_report.append(f"• {event['time']} - Event ID {event['event_id']}")
            custom_report.append(f"  {event['source']}: {event['message'][:80]}...")
            custom_report.append("")

    # Zapisz do pliku
    report_text = "\n".join(custom_report)
    with open("raport_niestandardowy.txt", "w", encoding="utf-8") as f:
        f.write(report_text)

    print("\nNiestandardowy raport zapisany do: raport_niestandardowy.txt")
    print(report_text)


def example_html_report():
    """Przykład 10: Generowanie raportu HTML"""
    print("\n" + "=" * 80)
    print("PRZYKŁAD 10: Generowanie raportu HTML")
    print("=" * 80)

    analyzer = WindowsEventAnalyzer(hours_back=24)
    analyzer.analyze_events()

    print(f"\nZnaleziono {len(analyzer.events)} zdarzeń")

    # Generuj raport HTML
    print("\nGenerowanie raportu HTML...")
    analyzer.save_report(filename="raport_zdarzen.html", format='html')

    print("\n✓ Raport HTML został wygenerowany!")
    print("\nRaport HTML zawiera:")
    print("  • Nowoczesny, responsywny design")
    print("  • Kolorowe karty statystyk")
    print("  • Interaktywne wykresy słupkowe")
    print("  • Szczegółowe karty dla każdego błędu")
    print("  • Rozwijane sekcje z wiadomościami zdarzeń")
    print("  • Gotowy do wydruku")
    print("\nOtwórz plik raport_zdarzen.html w przeglądarce aby zobaczyć raport!")


def example_both_formats():
    """Przykład 11: Generowanie obu formatów"""
    print("\n" + "=" * 80)
    print("PRZYKŁAD 11: Generowanie raportów w obu formatach")
    print("=" * 80)

    analyzer = WindowsEventAnalyzer(hours_back=24)
    analyzer.analyze_events()

    # Generuj oba formaty
    print("\n1. Generowanie raportu TXT...")
    txt_file = analyzer.save_report(format='txt')

    print("\n2. Generowanie raportu HTML...")
    html_file = analyzer.save_report(format='html')

    print("\n✓ Oba raporty zostały wygenerowane!")
    print(f"\n  TXT:  {txt_file}")
    print(f"  HTML: {html_file}")
    print("\nTXT - do archiwizacji i przetwarzania automatycznego")
    print("HTML - do prezentacji i analizy wizualnej")


def main():
    """Uruchom wszystkie przykłady"""
    print("\n")
    print("╔" + "═" * 78 + "╗")
    print("║" + " " * 20 + "PRZYKŁADY UŻYCIA ANALIZATORA" + " " * 30 + "║")
    print("╚" + "═" * 78 + "╝")
    print("\nUWAGA: Uruchom ten skrypt jako Administrator!\n")

    try:
        # Odkomentuj przykłady, które chcesz uruchomić

        example_basic_analysis()
        # example_custom_time_range()
        # example_critical_errors_only()
        # example_specific_event_id()
        # example_statistics()
        # example_hourly_breakdown()
        # example_security_audit()
        # example_disk_health_check()
        # example_custom_report()
        # example_html_report()         # NOWOŚĆ: Raport HTML
        # example_both_formats()         # NOWOŚĆ: Oba formaty

        print("\n" + "=" * 80)
        print("Wszystkie przykłady zostały wykonane pomyślnie!")
        print("=" * 80)

    except Exception as e:
        print(f"\nBłąd podczas wykonywania przykładów: {str(e)}")
        print("Upewnij się, że:")
        print("1. Uruchamiasz skrypt jako Administrator")
        print("2. Zainstalowałeś wymagane biblioteki: pip install -r requirements.txt")


if __name__ == "__main__":
    main()
