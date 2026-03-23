# SCA Scanner — Project Documentation

## Overview
.NET 10 console app evaluating system compliance against Wazuh SCA policies. Supports Windows, macOS, Linux. Parses rule strings, executes checks (file/dir/process/command/registry), applies conditions (ALL/ANY/NONE), outputs to console/log/CSV/SCAP-SCC.

**Key Features:** PowerShell/Bash execution, numeric regex capture groups, smart requirements checking, multi-format reporting.

---

## Core Files

| File | Purpose |
|------|---------|
| **Program.cs** | Entry point, argument parsing, orchestration, directory scanning |
| **Models.cs** | Enums (CheckStatus, CheckCondition, OutputLevel, RuleType, etc.) and YAML-deserializable data classes |
| **RuleParser.cs** | Parses rule strings → `ParsedRule`. Handles f:/d:/p:/c:/r: prefixes, `->` content, negation, AND conditions, env var expansion (`%VAR%` → `$env:VAR`) |
| **RuleChecker.cs** | Executes rules per type (file/dir/process/command/registry), applies condition logic (ALL/ANY/NONE), returns CheckResult |
| **IReporter.cs** | Interface segregation: `IPolicyReporter`, `ICheckReporter`, `ISummaryReporter`, `IDirectoryReporter`, `IErrorReporter`, `IReporter` (composite) |
| **BaseReporter.cs** | Abstract base with print logic; subclasses implement `Write()/WriteLine()` with/without color |
| **ConsoleReporter.cs** | Colored console output, respects `OutputLevel` |
| **FileReporter.cs** | Plain text file logging, always Detailed level |
| **AdvancedReporter.cs** | SCAP-SCC format with system metadata (hostname, OS, interfaces, memory, timestamps); truncates error messages |
| **CsvReporter.cs** | CSV export (one row per check result) with columns: Computer_Name, OS, Standard, Version, Scan_Date, Description, Fix_Text, Rule, Rule_ID, Status |
| **CompositeReporter.cs** | Routes method calls to multiple reporters; disposes IDisposable implementations |
| **StringUtils.cs** | `Truncate(text, maxLength)` helper |

---

## Build & Run
```bash
dotnet build SCAScanner.csproj
dotnet run --project SCAScanner.csproj [policy.yaml | policy_dir]
```

**Options:**
- `--display-details`: Detailed output level
- `--no-details`: Compact output level
- `-l, --log <file>`: Write to log file
- `--csv <file>`: CSV export
- `-r, --report <file>`: SCAP-SCC format
- `-h, --help`: Help

**Dependencies:** .NET 10, YamlDotNet 15.3.0 (Implicit Usings, Nullable Reference Types enabled)

---

## SCA Rule Format (Wazuh)

| Prefix | Syntax | Example |
|--------|--------|---------|
| `f:` | File exists / content match | `f:/etc/passwd -> r:root` |
| `d:` | Directory / files within | `d:/usr/bin -> r:bash` |
| `p:` | Process running | `p:sshd` |
| `c:` | Command output | `c:uname -a -> r:Linux` |
| `r:` | Windows registry (Windows only) | `r:HKEY_LOCAL_MACHINE\...\Key -> Value -> Data` |

**Content Operators:**
- Literal: `f:/file -> root` (substring match)
- Regex: `f:/file -> r:pattern\d+`
- Numeric: `c:cmd -> n:value (\d+) compare <= 100` (regex capture + compare)

**Negation:** `!f:/path` or `not r:PATTERN` (passes if NOT found)

**AND Conditions:** `r:pattern1 && r:pattern2` (single line must match both)

**Rule Conditions:**
- `all`: Every rule must pass
- `any`: At least one rule must pass
- `none`: Every rule must fail

---

## Architecture Patterns

- **Interface Segregation:** Reporters implement only required sub-interfaces
- **Composite Pattern:** `CompositeReporter` routes to multiple reporters
- **Strategy Pattern:** Different execution per rule type
- **Template Method:** `BaseReporter` defines structure; subclasses implement I/O

---

## File Structure
```
SCA_Scanner/
├── SCAScanner.csproj
├── Program.cs, Models.cs, RuleParser.cs, RuleChecker.cs
├── IReporter.cs, BaseReporter.cs
├── ConsoleReporter.cs, FileReporter.cs, AdvancedReporter.cs, CsvReporter.cs, CompositeReporter.cs
├── StringUtils.cs
└── Policies/ (example YAML files)
```
