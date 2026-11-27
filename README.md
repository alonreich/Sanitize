# 🛡️ Sanitization

**Make your code safe to go public.** Point it at your projects folder → it finds every password, API key and piece of
personal info in your files **and in your whole git history** → you click Fix → done.

```
  your projects ──► 🔍 scan ──► 🔴 🟠 🟡 ⚪ list ──► ✅ Fix ──► ⬆ Push ──► 🌍 safe to go public
```

## What it finds

| | Level | Examples |
|---|---|---|
| 🔴 | **Critical** | passwords, API keys, tokens (GitHub, AWS, OpenAI/Anthropic, Google, Slack, Stripe, Telegram, npm, Hugging Face, JWT, Azure), private keys, `user:pass@` in URLs, key/dump files (`.pfx` `.key` `.env` `.kdbx` `.dmp` `.pcap`…) |
| 🟠 | **High** | **you**: your e-mail & private info, PC name, Windows user name in paths, account SID, git author e-mails, your PC baked into compiled files |
| 🟡 | **Medium** | public IPs, other people's e-mails / user names, your local IP |
| ⚪ | **Probably fine** | test / sample data, archives it can't open — folded away |

## Which languages?

**All of them.** It reads text, not code, so any language or file type works:
C# · C/C++ · Java/Kotlin · JS/TS · Python · Go · Rust · PHP · Ruby · Swift · PowerShell · Bash/cmd · SQL ·
HTML/CSS · JSON/YAML/XML/INI/TOML · `.env` · Markdown · logs · Dockerfiles · notebooks · anything else that's text
(UTF-8, UTF-16, legacy encodings — saved back byte-for-byte).

Compiled stuff (`bin`, `obj`, `node_modules`, `.exe`, `.dll`…) is skipped — unless it's committed to git; then it's
checked for your name / PC (build paths love to leak). Zip / Office / PDF files are listed so you can check them by hand.

## Where it looks

📄 current files (committed, not-yet-committed, **and git-ignored** — they leak when you zip & share) ·
🕘 every old commit, branch and tag · ✉️ commit messages & author e-mails · 🌍 what GitHub still has.

## Two ways to run it

| | For | Run |
|---|---|---|
| 🖥️ `Compiled\sanitize.exe` | humans (window) | double-click. First time: pick your projects folder. |
| ⌨️ `Compiled\ai-sanitize.exe` | scripts & **AI agents** | `ai-sanitize scan` · `ai-sanitize fix --id ID` · `ai-sanitize help` |

Both use the same engine, the same findings (same ids) and the same encrypted settings.

### The GUI in 5 seconds

Projects → sorted by worst finding · inside each: 🔴 → 🟠 → 🟡 → ⚪ · tick + **Fix selected**, or **Fix all in this
project**, or **Fix ALL projects** · edit any replacement first · **Undo** for file fixes · **Push** when history changed ·
red **delete & recreate** guide when GitHub may still serve old commits.

### The CLI in 5 seconds (AI agents: start here)

```text
ai-sanitize scan  "C:\Dev"                      # every finding, one line each, exit 1 if anything Critical/High/Medium
ai-sanitize scan  "C:\Dev" --json               # same, as one JSON document
ai-sanitize fix   "C:\Dev" --id 20eea68b        # fix one (ids come from scan)
ai-sanitize fix   "C:\Dev" --project App --all --history   # fix everything in App, git history included
ai-sanitize push  "C:\Dev" --project App --yes  # force-push the cleaned history
```

Output (one record per line, `key=value` fields split by ` | `):

```text
SANITIZE v2026.11.27.1100 | format=1 | command=scan | root=C:\Dev | projects=3 | critical=1 | high=2 | medium=1 | low=4 | seconds=1.4
PROJECT WebShop | path=C:\Dev\WebShop | git=yes | branch=main | remote=github:me/webshop | uncommitted=no | unpushed_commits=0 | remote_only_commits=0 | needs_push=no
  F 20eea68b | CRITICAL | GitHub token | value=ghp_… | at=src/config.js:3 | where=file,history:2,remote | state=tracked | can_fix=yes | fix=Replace in the file, remove from git history. | replace=REDACTED_SECRET | needs=--history | context=const token = "ghp_…"; | why=…
  LOW 4 probably-fine item(s) hidden | show_with=--low
END | exit=1
```

Exit codes: `0` clean / done · `1` findings remain / refused · `2` error. Full reference: `ai-sanitize help`.

## Safety

- Nothing changes until you click **Fix** (GUI) or run `fix` (CLI).
- File fixes → **Undo** (in memory, until the GUI closes).
- History rewrites → **permanent, no backup**, red confirmation (GUI) or `--history` (CLI). Repos with uncommitted
  changes are never rewritten.
- Your private values & ignore list → encrypted (Windows DPAPI) in `%AppData%\Sanitization`, never in a project.
- Report → served once from memory to your browser, never saved to disk.
- Every build fails if the `.exe` files contain your user name or PC name.

## Needs

**Git** (required) · **GitHub CLI** `gh` + `gh auth login` (only for GitHub features).

## Build

`dev_build.cmd` (tests + NativeAOT → `Compiled\`) · `build.cmd --no-publish` (clean release build) ·
`build.cmd` (official GitHub release). Needs .NET 10 SDK + Visual Studio C++ build tools.

Engineers & AI agents: read **`project_structure.txt`** first.
