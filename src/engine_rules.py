"""Zaufane reguly i programy adapterow. Tresc probki trafia wylacznie jako dane."""

# id -> (tytul, waznosc, opis)
RULE_DETAILS = {
    "YARA-PS-001": (
        "Pobieranie i dynamiczne wykonanie", "high",
        "Sygnatura YARA laczy nazwe metody pobierania z Invoke-Expression.",
    ),
    "YARA-JS-001": (
        "Synchroniczne uruchamianie procesu Node.js", "high",
        "Sygnatura YARA laczy nazwe modulu child_process z execSync.",
    ),
    "YARA-SH-001": (
        "Interaktywna powloka i polaczenie TCP", "high",
        "Sygnatura YARA laczy uruchomienie bash -i z pseudo-urzadzeniem /dev/tcp.",
    ),
    "SEMGREP-JS-001": (
        "Proces potomny Node.js", "high",
        "Semgrep wykryl bezposrednie wywolanie exec z modulu child_process.",
    ),
    "SEMGREP-SH-001": (
        "Dynamiczne wykonanie Bash", "high",
        "Semgrep wykryl instrukcje eval w drzewie skladni Bash.",
    ),
    "ESPRIMA-JS-001": (
        "Dynamiczne wykonanie JavaScript w AST", "high",
        "Wywolanie eval albo Function moze interpretowac dane jako kod.",
    ),
    "PSAST-001": (
        "Dynamiczne polecenie PowerShell w AST", "high",
        "Parser rozpoznal wywolanie Invoke-Expression albo aliasu iex.",
    ),
    "PSAST-002": (
        "Tworzenie ScriptBlock z tekstu", "high",
        "Parser rozpoznal statyczne wywolanie ScriptBlock.Create.",
    ),
}

# Przekazywane do kompilatora YARA ze stalego argumentu. Brak modulow i include.
YARA_RULES = r"""
rule script_download_and_eval {
    strings:
        $download = "DownloadString" ascii wide nocase fullword
        $execute = "Invoke-Expression" ascii wide nocase fullword
    condition:
        all of them
}
rule node_sync_child_process {
    strings:
        $process = "child_process" ascii wide fullword
        $execute = "execSync" ascii wide fullword
    condition:
        all of them
}
rule bash_interactive_tcp {
    strings:
        $socket = "/dev/tcp/" ascii wide
        $shell = "bash -i" ascii wide fullword
    condition:
        all of them
}
"""

YARA_WORKER = """
import json
import sys
import yara

rules = yara.compile(source=sys.argv[1], includes=False)
matches = rules.match(data=sys.stdin.buffer.read(), timeout=5)
rule_ids = {
    "script_download_and_eval": "YARA-PS-001",
    "node_sync_child_process": "YARA-JS-001",
    "bash_interactive_tcp": "YARA-SH-001",
}
print(json.dumps({"items": [{"id": rule_ids[match.rule], "line": 1}
                            for match in matches], "incomplete": False}))
"""

SEMGREP_RULES = {
    "rules": [
        {
            "id": "SEMGREP-JS-001",
            "languages": ["javascript"],
            "severity": "ERROR",
            "message": RULE_DETAILS["SEMGREP-JS-001"][2],
            "pattern-either": [
                {"pattern": 'require("child_process").exec(...)'},
                {"pattern": 'require("node:child_process").exec(...)'},
            ],
        },
        {
            "id": "SEMGREP-SH-001",
            "languages": ["bash"],
            "severity": "ERROR",
            "message": RULE_DETAILS["SEMGREP-SH-001"][2],
            "pattern": "eval ...",
        },
    ],
}

ESPRIMA_WORKER = """
import json
import sys
import esprima

source = sys.stdin.buffer.read().decode("utf-8")
if source.startswith("#!"):
    source = "\\n" + source.partition("\\n")[2]
try:
    tree = esprima.parseScript(source, loc=True)
except esprima.Error:
    try:
        tree = esprima.parseModule(source, loc=True)
    except esprima.Error:
        print('{"items": [], "incomplete": true}')
        sys.exit(0)

items = []
pending = [tree]
while pending and len(items) <= 500:
    node = pending.pop()
    if node.type in {"CallExpression", "NewExpression"}:
        callee = node.callee
        name = None
        if callee.type == "Identifier":
            name = callee.name
        elif (callee.type == "MemberExpression" and callee.object.type == "Identifier"
              and callee.object.name in {"globalThis", "window", "global"}):
            prop = callee.property
            if callee.computed and prop.type == "Literal":
                name = prop.value if isinstance(prop.value, str) else None
            elif not callee.computed and prop.type == "Identifier":
                name = prop.name
        if name in {"eval", "Function"}:
            items.append({"id": "ESPRIMA-JS-001", "line": node.loc.start.line})
    for key, child in reversed(tuple(vars(node).items())):
        if key == "loc":
            continue
        if isinstance(child, esprima.nodes.Node):
            pending.append(child)
        elif isinstance(child, list):
            pending.extend(item for item in reversed(child) if isinstance(item, esprima.nodes.Node))
print(json.dumps({"items": items, "incomplete": False}))
"""

POWERSHELL_WORKER = r"""
$ErrorActionPreference = 'Stop'
$env:PSModulePath = [IO.Path]::Combine($PSHOME, 'Modules')
[Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$source = [Console]::In.ReadToEnd()
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput(
    $source, [ref]$tokens, [ref]$errors)
$items = [Collections.Generic.List[object]]::new()
foreach ($node in $ast.FindAll({
    param($item)
    $item -is [System.Management.Automation.Language.CommandAst] -or
    $item -is [System.Management.Automation.Language.InvokeMemberExpressionAst]
}, $true)) {
    $id = $null
    if ($node -is [System.Management.Automation.Language.CommandAst]) {
        $name = $node.GetCommandName()
        if ($name -match '^(Microsoft\.PowerShell\.Utility\\)?(iex|Invoke-Expression)$') {
            $id = 'PSAST-001'
        }
    } elseif ($node.Static -and
              $node.Expression -is [System.Management.Automation.Language.TypeExpressionAst] -and
              $node.Expression.TypeName.FullName -in @('ScriptBlock', 'System.Management.Automation.ScriptBlock') -and
              $node.Member -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
              $node.Member.Value -eq 'Create') {
        $id = 'PSAST-002'
    }
    if ($id) {
        $items.Add(@{id = $id; line = $node.Extent.StartLineNumber})
        if ($items.Count -gt 500) { break }
    }
}
@{items = $items.ToArray(); incomplete = ($errors.Length -gt 0)} |
    Microsoft.PowerShell.Utility\ConvertTo-Json -Compress -Depth 4
"""
