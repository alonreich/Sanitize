# Changelog

## Unreleased

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
