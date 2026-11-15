# Bezpieczeństwo

## Najważniejsza właściwość

Analizowany kod nigdy nie jest wykonywany. Program nie używa `eval`, `exec`,
`subprocess` ani powłoki dla treści wejściowej. Defuskacja operuje na kopii
łańcucha znaków, a wynik jest wyłącznie raportowany.

## Granice zaufania

Niezaufane są: skrypt, nazwa i ścieżka pliku, logi, ciągi po dekodowaniu,
odpowiedzi API oraz nazwy IOC. Zaufana jest konfiguracja operatora i lokalny
interpreter Pythona. Raport terminalowy usuwa znaki sterujące, raport PDF
transliteruje i escapuje znaki sterujące składnią, a nazwy katalogów są
sanitowane.

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
