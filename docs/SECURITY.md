# Bezpieczeństwo

## Najważniejsza właściwość

Analizowany kod jest przekazywany jako dane. Silniki statyczne otrzymują bajty
na standardowym wejściu albo kopię w katalogu roboczym. Argumenty procesu
zawierają stały program adaptera, reguły lub nazwy kontrolowane przez aplikację.
Defuskacja operuje na kopii łańcucha znaków.

## Granice zaufania

Niezaufane są: skrypt, nazwa i ścieżka pliku, logi, ciągi po dekodowaniu,
odpowiedzi API oraz nazwy IOC. Zaufana jest
konfiguracja operatora i lokalny interpreter Pythona. Raport terminalowy usuwa
znaki sterujące, raport PDF transliteruje i escapuje znaki sterujące składnią,
a nazwy katalogów są sanitowane.

## Model zagrożeń

| Zagrożenie | Kontrola | Ryzyko resztkowe |
|---|---|---|
| przypadkowe wykonanie próbki | stałe programy adapterów, pasywne API i `shell=False` | zaufane lokalne zależności |
| wyczerpanie pamięci | limit skryptu, logu, linii i odpowiedzi API | Regex może zużyć CPU na złożonym wejściu |
| nadpisanie źródła | osobny, wersjonowany katalog wyjścia | błędnie wskazany katalog może mieć słabe ACL |
| terminal escape injection | usuwanie znaków sterujących przez `terminal_text` | raport nadal może zawierać niepokojącą treść próbki |
| path traversal przez nazwę próbki | `safe_component` | katalog root wybiera operator |
| ujawnienie sekretu | klucz w środowisku i nagłówku, brak raportowania | środowisko procesu może być dostępne administratorowi |
| ujawnienie IOC stronie trzeciej | sieć wyłączona domyślnie, jawna flaga | zapytany IOC trafia do dostawcy |
| fałszywe poczucie bezpieczeństwa | raport i README opisują ograniczenia | reguły nie wykrywają wszystkich zagrożeń |
| manipulacja czasem | UTC, opcjonalny NTP, oznaczony fallback | NTP nie jest kryptograficznie uwierzytelniony |
| błędna interpretacja dowodu | osobne rodzaje zdarzeń, źródła i zakres odczytu | log może być niepełny, zmieniony lub nadpisany |
| wstrzyknięcie polecenia przez log | dane nigdy nie trafiają do poleceń; stałe adaptery `wevtutil qe`/`journalctl`, `shell=False` | lokalny system i narzędzia muszą być zaufane |
| XML entity expansion | odrzucanie DTD/ENTITY i limit pliku | parser nie uwierzytelnia źródła logu |
| przypadkowe kliknięcie IOC | rozbrajanie URL, domen oraz IPv4/IPv6 we wszystkich wyjściach | użytkownik może ręcznie odtworzyć adres |

## Silniki statyczne

- YARA kompiluje wyłącznie reguły projektu, z wyłączonymi dyrektywami
  `include`. Esprima odczytuje drzewo składni JavaScript.
- Semgrep dostaje pojedynczą kopię analizowanego pliku i lokalne reguły
  z projektu. Sprawdzanie wersji, metryki, telemetria oraz globalna
  konfiguracja Git są wyłączone. Katalog roboczy jest korzeniem projektu
  Semgrep. CLI skanuje bez logowania, rejestru reguł i automatycznych poprawek.
- ShellCheck analizuje stdin w trybie Bash, z wyłączoną konfiguracją z hosta.
  Adapter neutralizuje jawne dyrektywy ShellCheck z próbki i wstawia własną
  dyrektywę `source=/dev/null`, aby użyć pustej treści dla odwołań `source`.
  Opcja odczytu zewnętrznych źródeł `-x` jest wyłączona.
- PowerShell uruchamia zaufany program bez profilu i bez interakcji. Program
  używa `Parser.ParseInput` i odczytuje węzły AST. Adapter konserwatywnie
  pomija tekst zawierający `using`, `configuration` lub możliwe `#requires`,
  ponieważ parser może rozwiązywać zależności podczas parsowania. Dotyczy to
  również wystąpień w komentarzach i literałach.

Procesy mają osobne katalogi robocze, ograniczone środowisko bez kluczy
reputacji, limit czasu, wejścia i buforowanego wyjścia. Surowe błędy
narzędzi pozostają poza raportem. Status niepełnej analizy jest widoczny
w terminalu, JSON i PDF. Limity nie stanowią izolacji systemowej. Ścieżki
instalacji narzędzi, bezwzględne katalogi w `PATH` oraz katalog wynikowy
muszą należeć do zaufanej konfiguracji operatora.

## Logi połączeń

Operator wskazuje pliki przez `--connection-log`/`--execution-log` albo
włącza jednorazowy odczyt systemu przez `--system-history`. Program nie
podnosi uprawnień, nie zmienia audytu i nie instaluje usług. Brak dostępu
do źródła jest widoczny w raporcie. Narzędzia mają timeout i limity wyjścia.
Pliki tymczasowe historii mogą zawierać wrażliwe dane z dzienników; dostęp
do lokalnego katalogu tymczasowego i katalogu raportu musi być chroniony.

Status `NIE WYKRYTO` opisuje brak dowodu w rozpoznanych danych. DNS, blokada,
zezwolenie i sama wzmianka nie potwierdzają połączenia. Wywołanie interpretera
z argumentem pliku nie gwarantuje odczytu skryptu ani ukończenia działania.
Ścieżka nie potwierdza historycznej treści pliku; hash procesu Sysmon nie jest
hashem skryptu. Logi podane przez użytkownika są dowodem tylko w granicach
ich wiarygodności; parser nie weryfikuje autentyczności zdarzeń.

Rozbrajanie jest obowiązkową granicą wyjściową: URL używa `hxxp`/`hxxps`, kropki
w domenach i IPv4 mają postać `[.]`, a dwukropki IPv6 `[:]`. Obejmuje terminal,
JSON, PDF oraz `deobfuscated.txt`. Normalizacja wejścia służąca
korelacji odbywa się wyłącznie w pamięci.

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
