// Dane testowe YARA: child_process i execSync.
// Funkcja sluzy do analizy statycznej i nie jest wywolywana.
function engineCheck() {
    require("child_process").exec("echo engine-check");
    globalThis["eval"]("1 + 1");
}
