# Bezpieczeństwo

## Najważniejsza właściwość

Analizowany kod nigdy nie jest wykonywany. Program nie używa `eval`, `exec`,
`subprocess` ani powłoki dla treści wejściowej. Defuskacja operuje na kopii
łańcucha znaków, a wynik jest wyłącznie raportowany.

## Granice zaufania

Niezaufane są: skrypt, nazwa i ścieżka pliku, logi, ciągi po dekodowaniu,
odpowiedzi API, nazwy IOC oraz nazwy i ścieżki lokalnych procesów. Zaufana jest
konfiguracja operatora i lokalny interpreter Pythona. Raport terminalowy usuwa
znaki sterujące, raport PDF transliteruje i escapuje znaki sterujące składnią,
a nazwy katalogów są sanitowane.

## Model zagrożeń

| Zagrożenie | Kontrola | Ryzyko resztkowe |
|---|---|---|
| przypadkowe wykonanie próbki | brak interpreterów/powłoki i pasywne API | błąd przyszłego adaptera |
| wyczerpanie pamięci | limit skryptu, logu, linii i odpowiedzi API | Regex może zużyć CPU na złożonym wejściu |
| nadpisanie źródła | osobny, wersjonowany katalog wyjścia | błędnie wskazany katalog może mieć słabe ACL |
| terminal escape injection | usuwanie znaków sterujących przez `terminal_text` | raport nadal może zawierać niepokojącą treść próbki |
| path traversal przez nazwę próbki | `safe_component` | katalog root wybiera operator |
| ujawnienie sekretu | klucz w środowisku i nagłówku, brak raportowania | środowisko procesu może być dostępne administratorowi |
| ujawnienie IOC stronie trzeciej | sieć wyłączona domyślnie, jawna flaga | zapytany IOC trafia do dostawcy |
| fałszywe poczucie bezpieczeństwa | raport i README opisują ograniczenia | reguły nie wykrywają wszystkich zagrożeń |
| manipulacja czasem | UTC, opcjonalny NTP, oznaczony fallback | NTP nie jest kryptograficznie uwierzytelniony |
| niepełna telemetria połączeń | jawny model migawkowy, PID i uprawnienia mogą być niedostępne | krótkie połączenia między próbkami mogą zniknąć |
| ujawnienie lokalnej aktywności | raporty monitora w ignorowanym katalogu `report/` | JSONL zawiera adresy, PID i ścieżki programów |
| nadmierne uprawnienia monitora | działa bez podnoszenia uprawnień; administrator/root jest opcjonalny | wyższe uprawnienia zwiększają skutki błędu zależności |
| przypadkowe kliknięcie IOC | rozbrajanie URL, domen oraz IPv4/IPv6 we wszystkich wyjściach | użytkownik może ręcznie odtworzyć adres |

## Monitor systemowy

Monitor korzysta wyłącznie z odczytu lokalnych tabel gniazd przez `psutil`.
Nie wykonuje przechwytywania pakietów, nie zmienia zapory, nie zamyka połączeń i
nie wysyła danych. Na Linuksie część połączeń może zostać pominięta bez roota;
na obu systemach proces może zakończyć się pomiędzy odczytem gniazda i nazwy.

Raport `connections.jsonl` może ujawniać wewnętrzne adresy, uruchomione programy
i ścieżki użytkownika. Nie należy umieszczać go w publicznym repozytorium.
`report/` jest z tego powodu ignorowany przez Git.

Rozbrajanie jest obowiązkową granicą wyjściową: URL używa `hxxp`/`hxxps`, kropki
w domenach i IPv4 mają postać `[.]`, a dwukropki IPv6 `[:]`. Obejmuje terminal,
JSON, PDF, JSONL monitora oraz `deobfuscated.txt`. Normalizacja wejścia służąca
korelacji odbywa się wyłącznie w pamięci.

Monitor nie jest źródłem pełnej historii. Brak bieżącego rekordu ani brak wpisu
w dzienniku nie dowodzi, że program nigdy nie działał. Audyt historyczny musi
być włączony przed zdarzeniem i mieć odpowiednią retencję.

## Prywatność integracji reputacyjnych

VirusTotal dokumentuje, że zapytany IOC może zostać włączony do jego zbioru i
stać się dostępny społeczności. URLhaus również otrzymuje treść zapytanego URL
lub hosta. Nie włączaj reputacji dla wewnętrznych nazw, tokenów w query string,
danych osobowych ani tajnych adresów. Aplikacja nigdy nie przesyła całego pliku.

## Reagowanie na błędy

Niedostępny log staje się ostrzeżeniem, aby lokalna analiza mogła się zakończyć.
Awaria pojedynczego zapytania reputacyjnego ma wynik `error:<typ>` bez klucza i
bez treści odpowiedzi. Nieudany NTP jest oznaczony jako `system-fallback`.

## Zgłaszanie podatności

Nie dołączaj prawdziwej próbki malware ani sekretu do publicznego zgłoszenia.
Podaj minimalny, zanonimizowany przypadek i informację, czy naruszony został
niezmiennik „brak wykonania kodu”.
