#!/usr/bin/env bash
# Dane testowe YARA: bash -i i /dev/tcp/.
# Funkcja sluzy do analizy statycznej i nie jest wywolywana.
engine_check() {
    local value="sample value"
    printf '%s\n' $value
    eval "true"
}
