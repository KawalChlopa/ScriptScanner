# ADR-0002: Twarda granica analizy pasywnej

- Status: zaakceptowany
- Data: 2026-11-15

## Kontekst

Wejściem może być aktywnie szkodliwy kod. Nawet wygodne metody defuskacji oparte
na interpreterze zwiększają ryzyko przypadkowego wykonania.

## Decyzja

Żaden etap nie wykonuje próbki ani wyniku defuskacji. Dozwolone są wyłącznie
operacje na bajtach i łańcuchach znaków, parsowanie JSON odpowiedzi oraz jawne,
odczytowe zapytania IOC. Przyszły adapter zewnętrzny musi używać listy
argumentów, `shell=False`, timeoutu i limitu wyjścia.

## Konsekwencje

Niektóre wieloetapowe lub zależne od środowiska techniki obfuskacji pozostaną
niewykryte. Jest to świadoma wymiana kompletności na bezpieczeństwo.
