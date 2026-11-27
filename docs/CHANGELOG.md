# Changelog

## Unreleased
### What's new for you
- When a value is found once, every other copy of it in the project is listed too, including tests and docs, so one fix
  cleans all of them.
- Each different value gets its own safe stand-in (203.0.113.10, .11, …; user@, user2@example.com, …), and the same
  value always gets the same one, even in later scans, so tests and configs keep making sense.
- Finds your organisation's name, cloud tenant names (ServiceNow, Okta, SharePoint, …), tenant / customer IDs and
  record IDs in company URLs, and learns the organisation from the e-mail addresses it finds.
- Reads inside Word, Excel and PowerPoint files, including the hidden author / company fields.
- Flags a real full name used as the git commit author and can change it to "Dev User" in all commits.
- Fewer false alarms: digits inside IDs / hashes are no longer phone numbers, and package versions are no longer IPs.

### Technical
- New `ScanContext` (PlaceholderMap + OrgTerms) shared across projects in one scan; map stored in the encrypted
  settings as sha256(kind|value) -> placeholder (`AppSettings.Placeholders`, `AppSettings.OrgTerms`).
- `Scanner.PostPassAsync`: org learning from Medium e-mails, Low -> source severity promotion, and a working-tree
  sweep for every Medium+ value and learned org term (`Finding.Propagated`).
- New rules: Company cloud tenant, Cloud tenant / customer ID, Record ID in a company URL, learned organisation name.
- `OfficeText`: docx/xlsx/pptx text + docProps authors, working tree and history; findings are `InsideDocument` and
  not auto-fixable.
- Commit author full names -> `Real name as commit author`; `HistoryRewriter.Plan.NameMap` rewrites them.
- `RuleSet.ScanText` drops generic hits inside GUIDs / hex runs; `ValidateIp` drops IPs after a dotted package id;
  UK drama-range phones (+44 20 7946 0xxx) are dropped as placeholders.

## v2026.11.27.1135 (2026-11-27)
### What's new for you
- First version of Sanitization: point it at your projects folder and it lists every secret and piece of personal
  info in your files and in your git history, sorted by how serious it is, project by project.
- Fix one item, a selection, a whole project or everything at once. File fixes can be undone.
- Cleans git history too, and walks you through deleting and recreating a GitHub repo when that's the only way to
  remove old commits completely.
- Your private values are stored encrypted for your Windows account, never inside a project.
- Full report opens in your browser and is never saved to disk.
- Tighter, calmer layout: far less empty space, smaller buttons, one compact line per detail.
- New `ai-sanitize.exe`: the same scan and fixes from the command line, in a plain-text format AI agents can read.

### Technical
- C# 14 / .NET 10, Avalonia 12, NativeAOT. Native history rewrite via git fast-export / fast-import (no git-filter-repo).
- Headless CLI (src/Sanitization.Cli, Core/Cli.cs): text format v1 + JSON, stable 8-hex finding ids, exit codes.
- Low findings condensed per file/category (>= 15) to keep the list usable.
- Settings encrypted with DPAPI in %AppData%\Sanitization. One-shot loopback server for the report (Cache-Control: no-store).
