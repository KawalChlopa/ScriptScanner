// PRZYKLAD EDUKACYJNY - podaj ten plik analizatorowi, nie runtime Node.
// Podejrzane elementy sa tylko tekstem i nie sa wykonywane.

// Zakodowany tekst Base64 zostanie rozpoznany i pasywnie odczytany.
const base64Text = "ZXZhbCgiaHR0cHM6Ly9iYWQtanMuZXhhbXBsZS9hIik=";

// Sekwencje hex ukrywaja testowy wskaznik sieciowy.
const escapedText = "\x68\x74\x74\x70\x73\x3a\x2f\x2f\x31\x39\x38\x2e\x35\x31\x2e\x31\x30\x30\x2e\x32\x30\x2f\x63\x32";

// Konkatenacja ukrywa podejrzana nazwe funkcji.
const fragmentedName = "ev" + "al" + "(";

// Wzorzec procesu pozostaje nieaktywnym lancuchem znakow.
const processText = "child_process.exec('not-executed')";

console.log("Bezpieczna probka tekstowa dla Infa-Sled.");
