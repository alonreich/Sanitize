# Changelog

## Unreleased

## v2026.11.28.0106 (2026-11-28)
### What's new for you
- Knows who you are: your real name (from git and Windows), your GitHub user name (from GitHub's private noreply
  address and your repo links), your other e-mails (OneDrive accounts) and your employer (Windows / Office / OneDrive
  for Business). Finds them in files, history, commit authors, tags and build output.
- GitHub "noreply" commit e-mails are no longer trusted when they contain your user name; commit authors are
  rewritten to "Dev User <dev@example.com>".
- Reads text in screenshots and pictures (Windows' built-in OCR), also in old commits and Git LFS.
- Scans every saved git snapshot (stash, tool checkpoints), not just branches and tags, and can clean them.
- Finds logs and test results committed to git, build folders (bin / obj / TestResults) that hold your user path,
  git backup bundles, leftovers in .git (lost-found, stale worktree links, the repo's own name / e-mail settings),
  and files that look like a dump of company servers / internal IPs.
- Fewer false alarms: our own safe stand-ins (contoso.local, fabrikam-*, user2, dev@example.com, …) are never
  reported, code like `imported.local` is no longer a server name, and packed DLLs (.dll.gz) are unpacked and checked.
- Every different value always gets its own stand-in (old duplicate stand-ins are repaired); other people's user
  names become C:\Users\user2, user3, ….
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
- `MachineIdentity`: FullNames / Handles / ExtraEmails / Organisations (git global + per-repo config, RegisteredOwner /
  RegisteredOrganization, Office UserInfo, OneDrive Accounts); `WithProject()` adds repo user.name/email + GitHub owner.
  New High rules: your name, name in author / company fields, name-based e-mail, GitHub user name, GitHub noreply
  e-mail; Medium: your organisation.
- History scan uses `--exclude=refs/remotes/* --all` (stash, notes, tool refs, tree refs); commit identities via
  `Scanner.AddIdentity` (noreply handles, known single-word names); annotated tag taggers + messages.
  `HistoryRewriter.RewriteTreeRefsAsync` rebuilds refs that point at trees in a private index.
- `TextCodec`: BOM-less UTF-16 LE (`Utf16LeNoBom`, byte-exact round trip).
- `ImageText`: Windows.Media.Ocr (TFM now net10.0-windows10.0.19041.0; NativeAOT OK) for working tree, history
  blobs and LFS objects -> WholeFile "Picture shows personal data".
- New findings: log / test result committed (drop from history), build output contains your PC info
  (`FixActions.DeleteFolders`), captured network / customer data, git backup bundle, recovered old files
  (.git/lost-found), git worktree link, repo git settings (`FindingKind.GitConfig`, `FixActions.SetGitConfig`, undoable).
- `Heuristics.IsSafeHost / IsSafeEmail / IsGenericUserName / InsideStringLiteral / IsCodeFile`; `.gz` programs unpacked.
- `PlaceholderMap.RepairDuplicates`; new `user` kind (user2, user3, …); own profile path -> `C:\Users\user`.
- Release privacy gate also checks name, git e-mail, GitHub user, registered owner / organisation, OneDrive e-mail /
  organisation (whole words, never printed).
- New `DeeperDetectionTests` (23 tests).
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
