using System.Diagnostics;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Sanitization.Core;

/// <summary>
/// Headless front-end (ai-sanitize.exe). Same scan, same findings, same fixes as the GUI, printed as line-based text
/// (one record per line, "key=value" fields separated by " | ") or JSON. Shares the GUI's encrypted settings.
/// </summary>
public static class CliApp
{
    public const string Help = """
        ai-sanitize.exe — headless Sanitization (same engine and settings as sanitize.exe)

        COMMANDS
          ai-sanitize scan   [FOLDER] [--project NAME]... [--low] [--json]
          ai-sanitize fix    [FOLDER] (--id ID... | --all) [--project NAME]... [--low] [--history] [--replace ID=VALUE]... [--json]
          ai-sanitize push   [FOLDER] --project NAME --yes [--no-lease]
          ai-sanitize ignore [FOLDER] --id ID...            ai-sanitize unignore --path PROJECT_PATH --value VALUE
          ai-sanitize ignored                               ai-sanitize tools
          ai-sanitize private list | add VALUE [REPLACEMENT] | remove VALUE
          ai-sanitize recreate-guide [FOLDER] --project NAME
          ai-sanitize help

        FOLDER defaults to the folder last chosen in the GUI. NAME = project folder name (case-insensitive).
        --low      also list "probably fine" items (default: counted only).
        --all      every fixable Critical/High/Medium item (plus Low with --low).
        --history  allow rewriting git history (permanent, no backup). Without it only files are fixed.
        --json     machine output (one JSON document).

        EXIT CODES  scan: 0 = nothing Critical/High/Medium, 1 = findings, 2 = error
                    fix: 0 = everything requested is gone, 1 = some remain / blocked, 2 = error
                    push: 0 = pushed, 1 = refused / failed, 2 = error

        TEXT FORMAT (v1): one record per line, fields "key=value" separated by " | "; inside values newline/CR/tab/pipe are written as \n \r \t \| (backslashes are literal).
          SANITIZE  header      PROJECT  one per project      F  one finding      LOW  folded count
          NOTE      remark      RESULT   fix/push outcome     END  summary + exit code
        """;

    private sealed class Args
    {
        public string Command = "help";
        public string? Folder;
        public List<string> Projects = [];
        public List<string> Ids = [];
        public Dictionary<string, string> Replace = new(StringComparer.OrdinalIgnoreCase);
        public List<string> Positional = [];
        public bool Low, Json, All, History, Yes, NoLease;
        public string? Path, Value;
    }

    public static async Task<int> RunAsync(string[] argv, TextWriter o, TextWriter e, CancellationToken ct = default)
    {
        Args a;
        try { a = Parse(argv); }
        catch (ArgumentException ex) { await e.WriteLineAsync("ERROR: " + ex.Message + "\n\n" + Help); return 2; }
        try
        {
            return a.Command switch
            {
                "scan" => await ScanAsync(a, o, e, ct),
                "fix" => await FixAsync(a, o, e, ct),
                "push" => await PushAsync(a, o, e, ct),
                "tools" => await ToolsAsync(o, ct),
                "private" => Private(a, o, e),
                "ignore" => await IgnoreAsync(a, o, e, ct),
                "unignore" => Unignore(a, o, e),
                "ignored" => Ignored(o),
                "recreate-guide" => await GuideAsync(a, o, e, ct),
                _ => Write(o, Help, 0),
            };
        }
        catch (ArgumentException ex) { await e.WriteLineAsync("ERROR: " + ex.Message + "\n\n" + Help); return 2; }
        catch (OperationCanceledException) { await e.WriteLineAsync("ERROR: cancelled"); return 2; }
        catch (Exception ex) { await e.WriteLineAsync("ERROR: " + ex.Message); return 2; }
    }

    private static int Write(TextWriter o, string s, int code) { o.WriteLine(s); return code; }

    private static Args Parse(string[] argv)
    {
        var a = new Args();
        if (argv.Length == 0) return a;
        a.Command = argv[0].TrimStart('-').ToLowerInvariant();
        for (var i = 1; i < argv.Length; i++)
        {
            string Next() => i + 1 < argv.Length ? argv[++i] : throw new ArgumentException($"{argv[i]} needs a value");
            switch (argv[i].ToLowerInvariant())
            {
                case "--project": a.Projects.Add(Next()); break;
                case "--id": a.Ids.AddRange(Next().Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)); break;
                case "--replace":
                    var kv = Next();
                    var eq = kv.IndexOf('=');
                    if (eq <= 0) throw new ArgumentException("--replace expects ID=VALUE");
                    a.Replace[kv[..eq]] = kv[(eq + 1)..];
                    break;
                case "--low": a.Low = true; break;
                case "--json": a.Json = true; break;
                case "--all": a.All = true; break;
                case "--history": a.History = true; break;
                case "--yes": a.Yes = true; break;
                case "--no-lease": a.NoLease = true; break;
                case "--path": a.Path = Next(); break;
                case "--value": a.Value = Next(); break;
                default:
                    if (argv[i].StartsWith("--", StringComparison.Ordinal)) throw new ArgumentException($"unknown option {argv[i]}");
                    a.Positional.Add(argv[i]);
                    break;
            }
        }
        if (a.Command is "scan" or "fix" or "push" or "ignore" or "recreate-guide" && a.Positional.Count > 0) a.Folder = a.Positional[0];
        return a;
    }

    // ------------------------------------------------------------------ scan

    private static string ResolveRoot(Args a, AppSettings s)
    {
        var root = a.Folder ?? s.ScanRoot ?? throw new ArgumentException("no FOLDER given and none chosen in the GUI yet");
        if (!Directory.Exists(root)) throw new ArgumentException($"folder not found: {root}");
        return Path.GetFullPath(root);
    }

    public static async Task<(string Root, List<ProjectScanResult> Results, TimeSpan Elapsed)> ScanProjectsAsync(string root, AppSettings s,
        IReadOnlyCollection<string> only, CancellationToken ct)
    {
        var id = await MachineIdentity.DetectAsync(ct);
        var sw = Stopwatch.StartNew();
        var projects = ProjectDiscovery.Discover(root).Where(p => only.Count == 0 || only.Any(n => n.Equals(p.Name, StringComparison.OrdinalIgnoreCase))).ToList();
        if (only.Count > 0 && projects.Count == 0) throw new ArgumentException($"no project named {string.Join(", ", only)} under {root}");
        var results = new List<ProjectScanResult>();
        foreach (var p in projects) results.Add(await Scanner.ScanAsync(p, id, s.PrivateTerms, s.IgnoredFor(p.Path), null, ct));
        return (root, FindingOrdering.SortProjects(results).ToList(), sw.Elapsed);
    }

    private static async Task<int> ScanAsync(Args a, TextWriter o, TextWriter e, CancellationToken ct)
    {
        var s = SettingsStore.Load();
        var (root, results, elapsed) = await ScanProjectsAsync(ResolveRoot(a, s), s, a.Projects, ct);
        var exit = results.Any(r => r.Findings.Any(f => f.Severity != Severity.Low)) ? 1 : 0;
        if (a.Json) await WriteJsonAsync(o, "scan", root, results, elapsed, exit, null);
        else WriteText(o, "scan", root, results, elapsed, a.Low, exit);
        return exit;
    }

    // ------------------------------------------------------------------ text output

    public static string Esc(string? v) => (v ?? "").Replace("\n", "\\n").Replace("\r", "\\r").Replace("\t", "\\t").Replace("|", "\\|");

    private static string Version => Assembly.GetEntryAssembly()?.GetName().Version?.ToString() ?? "dev";

    private static string SevWord(Severity s) => s switch { Severity.Critical => "CRITICAL", Severity.High => "HIGH", Severity.Medium => "MEDIUM", _ => "LOW" };

    public static string Where(Finding f)
    {
        var w = new List<string>();
        if (f.InWorkingTree) w.Add("file");
        if (f.HistoryVersions > 0) w.Add($"history:{f.HistoryVersions}");
        if (f.Kind == FindingKind.TextValue && f.CommitMessages.Count > 0) w.Add($"commit-message:{f.CommitMessages.Count}");
        if (f.Kind == FindingKind.CommitIdentity) w.Add($"commit-author:{f.CommitMessages.Count}");
        if (f.Kind == FindingKind.RemoteUrl) w.Add("git-remote-config");
        if (f.OnRemote) w.Add("remote");
        return string.Join(",", w);
    }

    private static string State(Finding f) => f.FileState switch
    {
        FileState.Tracked => "tracked", FileState.Untracked => "untracked-not-committed", FileState.Ignored => "gitignored-never-committed",
        FileState.NotGit => "not-git", _ => f.InWorkingTree ? "file" : "history-only",
    };

    public static string FindingLine(Finding f)
    {
        var at = f.RelativePath.Length == 0 ? (f.Kind == FindingKind.CommitIdentity ? "(commit author)" : "(commit message)") : f.RelativePath;
        if (f.Lines.Count > 0) at += ":" + string.Join(",", f.Lines.Order().Take(10));
        var value = f.Value.Length > 300 ? f.Value[..300] + "…" : f.Value;
        var sb = new StringBuilder($"  F {f.Id} | {SevWord(f.Severity)} | {Esc(f.Category)} | value={Esc(value)} | at={Esc(at)} | where={Where(f)} | state={State(f)}");
        sb.Append(f.CanFix ? $" | can_fix=yes | fix={Esc(f.FixDescription)}" : f.OnlyOnRemote ? $" | can_fix=push | fix={Esc(f.FixDescription)}" : $" | can_fix=no | why_not={Esc(f.NoFixReason)}");
        if (f.CanFix && f.Replacement is not null) sb.Append($" | replace={Esc(f.Replacement)}");
        if (FixPlanner.TouchesHistory(f)) sb.Append(" | needs=--history");
        if (f.Snippet is { Length: > 0 } sn && sn != f.Value && sn != "commit message") sb.Append($" | context={Esc(sn.Length > 200 ? sn[..200] + "…" : sn)}");
        sb.Append($" | why={Esc(f.Why)}");
        return sb.ToString();
    }

    public static string ProjectLine(ProjectInfo p)
    {
        var remote = p.GitHub is not null ? "github:" + p.GitHub.FullName : string.IsNullOrEmpty(p.OriginUrl) ? "none" : "other";
        var git = p.TopLevelOnly ? "loose-files" : p.IsGit ? $"yes | branch={Esc(p.Branch)}" : "no";
        return $"PROJECT {Esc(p.Name)} | path={Esc(p.Path)} | git={git} | remote={remote} | uncommitted={(p.HasUncommittedChanges ? "yes" : "no")}" +
               $" | unpushed_commits={p.LocalOnlyCommits} | remote_only_commits={p.RemoteOnlyCommits} | needs_push={(p.NeedsForcePush || p.LocalOnlyCommits > 0 ? "yes" : "no")}";
    }

    private static void WriteText(TextWriter o, string cmd, string root, List<ProjectScanResult> results, TimeSpan elapsed, bool low, int exit)
    {
        var all = results.SelectMany(r => r.Findings).ToList();
        o.WriteLine($"SANITIZE v{Version} | format=1 | command={cmd} | root={Esc(root)} | projects={results.Count} | critical={all.Count(f => f.Severity == Severity.Critical)}" +
                    $" | high={all.Count(f => f.Severity == Severity.High)} | medium={all.Count(f => f.Severity == Severity.Medium)} | low={all.Count(f => f.Severity == Severity.Low)} | seconds={elapsed.TotalSeconds:0.0}");
        foreach (var r in results)
        {
            o.WriteLine(ProjectLine(r.Project));
            if (r.Findings.Count == 0) o.WriteLine("  CLEAN");
            foreach (var f in r.Findings.Where(f => low || f.Severity != Severity.Low)) o.WriteLine(FindingLine(f));
            var lows = r.Findings.Count(f => f.Severity == Severity.Low);
            if (!low && lows > 0) o.WriteLine($"  LOW {lows} probably-fine item(s) hidden | show_with=--low");
            if (r.Project.NeedsForcePush || r.Findings.Any(f => f.OnlyOnRemote))
                o.WriteLine($"  NOTE history is clean locally but the remote still has old commits | next=ai-sanitize push \"{root}\" --project \"{r.Project.Name}\" --yes");
            if (r.Project.HasUncommittedChanges && r.Findings.Any(FixPlanner.TouchesHistory))
                o.WriteLine("  NOTE uncommitted changes: history items can't be fixed until you commit or stash; files can");
            foreach (var n in r.Project.Notes.Take(5)) o.WriteLine($"  NOTE {Esc(n)}");
        }
        o.WriteLine($"END | exit={exit}");
    }

    // ------------------------------------------------------------------ json output

    private static async Task WriteJsonAsync(TextWriter o, string cmd, string root, List<ProjectScanResult> results, TimeSpan elapsed, int exit, List<FixReport>? fixes)
    {
        var doc = new JsonReport
        {
            Command = cmd, Version = Version, Root = root, Seconds = Math.Round(elapsed.TotalSeconds, 1), Exit = exit, Fixes = fixes,
            Projects = results.Select(r => new JsonProject
            {
                Name = r.Project.Name, Path = r.Project.Path, IsGit = r.Project.IsGit, Branch = r.Project.Branch, GitHub = r.Project.GitHub?.FullName,
                Uncommitted = r.Project.HasUncommittedChanges, UnpushedCommits = r.Project.LocalOnlyCommits, RemoteOnlyCommits = r.Project.RemoteOnlyCommits,
                Notes = r.Project.Notes,
                Findings = r.Findings.Select(f => new JsonFinding
                {
                    Id = f.Id, Severity = SevWord(f.Severity).ToLowerInvariant(), Category = f.Category, Value = f.Value, Path = f.RelativePath,
                    Lines = f.Lines.Order().ToList(), Where = Where(f).Split(',', StringSplitOptions.RemoveEmptyEntries).ToList(), State = State(f),
                    CanFix = f.CanFix, OnlyOnRemote = f.OnlyOnRemote, NeedsHistory = FixPlanner.TouchesHistory(f), Fix = f.CanFix || f.OnlyOnRemote ? f.FixDescription : f.NoFixReason,
                    Replacement = f.CanFix ? f.Replacement : null, Context = f.Snippet, Why = f.Why,
                }).ToList(),
            }).ToList(),
        };
        await o.WriteLineAsync(JsonSerializer.Serialize(doc, CliJsonContext.Default.JsonReport));
    }

    // ------------------------------------------------------------------ fix

    public sealed class FixReport
    {
        public string Project { get; set; } = "";
        public int Requested { get; set; }
        public int Remaining { get; set; }
        public int FilesChanged { get; set; }
        public bool HistoryRewritten { get; set; }
        public string? HistoryBlocked { get; set; }
        public List<string> Errors { get; set; } = [];
    }

    private static async Task<int> FixAsync(Args a, TextWriter o, TextWriter e, CancellationToken ct)
    {
        if (!a.All && a.Ids.Count == 0) throw new ArgumentException("fix needs --id ID (from scan output) or --all");
        var s = SettingsStore.Load();
        var (root, results, _) = await ScanProjectsAsync(ResolveRoot(a, s), s, a.Projects, ct);
        var wanted = new HashSet<string>(a.Ids, StringComparer.OrdinalIgnoreCase);
        var unknown = wanted.Where(id => !results.Any(r => r.Findings.Any(f => f.Id.Equals(id, StringComparison.OrdinalIgnoreCase)))).ToList();
        if (unknown.Count > 0) throw new ArgumentException($"unknown id(s): {string.Join(", ", unknown)} (run scan again; ids change after a fix)");
        var reports = new List<FixReport>();
        var touched = new List<ProjectInfo>();
        foreach (var r in results)
        {
            var pick = r.Findings.Where(f => f.CanFix && (a.All ? (a.Low || f.Severity != Severity.Low) : wanted.Contains(f.Id))).ToList();
            if (pick.Count == 0) continue;
            foreach (var f in pick)
                if (a.Replace.TryGetValue(f.Id, out var rep)) f.Replacement = rep;
            var outcome = await Fixer.ApplyAsync(r.Project, pick, a.History, new UndoBatch(), null, ct);
            reports.Add(new FixReport
            {
                Project = r.Project.Name, Requested = pick.Count, FilesChanged = outcome.FilesChanged, HistoryRewritten = outcome.HistoryRewritten,
                HistoryBlocked = outcome.HistoryBlocked, Errors = outcome.Errors,
            });
            touched.Add(r.Project);
        }
        var (_, after, elapsed) = await ScanProjectsAsync(root, s, touched.Select(t => t.Name).ToList(), ct);
        var requestedKeys = results.SelectMany(r => r.Findings).Where(f => f.CanFix && (a.All ? (a.Low || f.Severity != Severity.Low) : wanted.Contains(f.Id)))
            .Select(f => f.ProjectPath + "|" + f.Key).ToHashSet(StringComparer.Ordinal);
        foreach (var rep in reports)
        {
            var proj = after.FirstOrDefault(r => r.Project.Name == rep.Project);
            rep.Remaining = proj?.Findings.Count(f => requestedKeys.Contains(f.ProjectPath + "|" + f.Key) && !f.OnlyOnRemote) ?? 0;
        }
        var exit = reports.Count == 0 ? 0 : reports.Any(r => r.Remaining > 0 || r.Errors.Count > 0 || r.HistoryBlocked is not null) ? 1 : 0;
        if (a.Json) { await WriteJsonAsync(o, "fix", root, after, elapsed, exit, reports); return exit; }
        if (reports.Count == 0) o.WriteLine("RESULT nothing fixable matched");
        foreach (var rep in reports)
        {
            o.WriteLine($"RESULT {Esc(rep.Project)} | requested={rep.Requested} | remaining={rep.Remaining} | files_changed={rep.FilesChanged} | history_rewritten={(rep.HistoryRewritten ? "yes" : "no")}" +
                        (rep.HistoryBlocked is null ? "" : $" | history_blocked={Esc(rep.HistoryBlocked)}") + (rep.Errors.Count == 0 ? "" : $" | errors={Esc(string.Join(" ; ", rep.Errors))}"));
        }
        WriteText(o, "fix", root, after, elapsed, a.Low, exit);
        return exit;
    }

    // ------------------------------------------------------------------ push / guide

    private static async Task<ProjectScanResult> OneProjectAsync(Args a, AppSettings s, CancellationToken ct)
    {
        if (a.Projects.Count != 1) throw new ArgumentException("give exactly one --project NAME");
        var (_, results, _) = await ScanProjectsAsync(ResolveRoot(a, s), s, a.Projects, ct);
        return results[0];
    }

    private static async Task<int> PushAsync(Args a, TextWriter o, TextWriter e, CancellationToken ct)
    {
        var s = SettingsStore.Load();
        var r = await OneProjectAsync(a, s, ct);
        var p = r.Project;
        if (!p.IsGit || string.IsNullOrEmpty(p.OriginUrl)) { o.WriteLine($"RESULT {Esc(p.Name)} | pushed=no | reason=no git remote 'origin'"); return 1; }
        var oldOnRemote = p.RemoteOnlyCommits > 0 || r.Findings.Any(f => f.OnRemote);
        if (!a.Yes)
        {
            o.WriteLine($"RESULT {Esc(p.Name)} | pushed=no | reason=force-push replaces remote history; repeat with --yes to confirm");
            if (oldOnRemote) o.WriteLine("NOTE the remote may keep old commits reachable by direct link / forks / PRs even after a force-push; see: ai-sanitize recreate-guide --project NAME");
            return 1;
        }
        var (ok, log) = await GitHubService.ForcePushAsync(p.Path, lease: !a.NoLease, ct);
        var stale = ok ? await GitHubService.StaleRemoteBranchesAsync(p.Path, ct) : [];
        o.WriteLine($"RESULT {Esc(p.Name)} | pushed={(ok ? "yes" : "no")} | log={Esc(log.Trim())}" + (stale.Count > 0 ? $" | stale_remote_branches={Esc(string.Join(",", stale))}" : ""));
        if (ok && oldOnRemote) o.WriteLine("NOTE for complete removal of old commits from GitHub caches, recreate the repo: ai-sanitize recreate-guide --project NAME");
        return ok && stale.Count == 0 ? 0 : 1;
    }

    private static async Task<int> GuideAsync(Args a, TextWriter o, TextWriter e, CancellationToken ct)
    {
        var s = SettingsStore.Load();
        var p = (await OneProjectAsync(a, s, ct)).Project;
        if (p.GitHub is null) { o.WriteLine("RESULT not a GitHub repository"); return 1; }
        var g = p.GitHub;
        o.WriteLine($"""
            GUIDE delete & recreate {g.FullName} (needs a human: GitHub requires typing the repo name in a browser)
            STEP 1 save anything you need from {GitHubService.ReleasesUrl(g)} and {g.Url}/issues (deleted with the repo)
            STEP 2 open {GitHubService.SettingsUrl(g)} -> Danger Zone -> Delete this repository -> type {g.FullName}
            STEP 3 open {GitHubService.NewRepoUrl(g, "private")} -> leave README / .gitignore / license OFF -> Create repository
            STEP 4 ai-sanitize push "{p.Path}" --project "{p.Name}" --yes --no-lease
            CHECK  gh repo view {g.FullName} --json createdAt   (must be newer than the deletion)
            """);
        return 0;
    }

    // ------------------------------------------------------------------ tools / settings

    private static async Task<int> ToolsAsync(TextWriter o, CancellationToken ct)
    {
        var t = await ToolStatus.ProbeAsync(ct);
        o.WriteLine($"TOOLS git={(t.GitInstalled ? "ok" : "missing")} | gh={(t.GhInstalled ? "ok" : "missing")} | gh_login={(t.GhLoggedIn ? Esc(t.GhAccount) : "no")} | settings={Esc(SettingsStore.FilePath)}");
        if (!t.GitInstalled) o.WriteLine("NOTE " + Esc(t.GitMissingMessage));
        else if (!t.GitHubReady) o.WriteLine("NOTE " + Esc(t.GitHubMissingMessage));
        return t.GitInstalled ? 0 : 1;
    }

    private static int Private(Args a, TextWriter o, TextWriter e)
    {
        var s = SettingsStore.Load();
        var sub = a.Positional.FirstOrDefault()?.ToLowerInvariant() ?? "list";
        switch (sub)
        {
            case "add":
                if (a.Positional.Count < 2 || a.Positional[1].Trim().Length < 3) throw new ArgumentException("private add VALUE [REPLACEMENT] (VALUE: 3+ chars)");
                s.PrivateTerms.RemoveAll(t => t.Value.Equals(a.Positional[1], StringComparison.OrdinalIgnoreCase));
                s.PrivateTerms.Add(new PrivateTerm { Value = a.Positional[1].Trim(), Replacement = a.Positional.Count > 2 ? a.Positional[2] : "REDACTED" });
                SettingsStore.Save(s);
                break;
            case "remove":
                if (a.Positional.Count < 2) throw new ArgumentException("private remove VALUE");
                s.PrivateTerms.RemoveAll(t => t.Value.Equals(a.Positional[1], StringComparison.OrdinalIgnoreCase));
                SettingsStore.Save(s);
                break;
            case "list": break;
            default: throw new ArgumentException("private list | add VALUE [REPLACEMENT] | remove VALUE");
        }
        foreach (var t in s.PrivateTerms) o.WriteLine($"PRIVATE value={Esc(t.Value)} | replace={Esc(t.Replacement)}");
        o.WriteLine($"END | count={s.PrivateTerms.Count}");
        return 0;
    }

    private static async Task<int> IgnoreAsync(Args a, TextWriter o, TextWriter e, CancellationToken ct)
    {
        if (a.Ids.Count == 0) throw new ArgumentException("ignore needs --id ID");
        var s = SettingsStore.Load();
        var (_, results, _) = await ScanProjectsAsync(ResolveRoot(a, s), s, a.Projects, ct);
        var n = 0;
        foreach (var f in results.SelectMany(r => r.Findings).Where(f => a.Ids.Contains(f.Id, StringComparer.OrdinalIgnoreCase)))
        {
            s.Ignore(f.ProjectPath, f.Value);
            o.WriteLine($"IGNORED {f.Id} | path={Esc(f.ProjectPath)} | value={Esc(f.Value)}");
            n++;
        }
        SettingsStore.Save(s);
        return n == a.Ids.Count ? 0 : 1;
    }

    private static int Unignore(Args a, TextWriter o, TextWriter e)
    {
        if (a.Path is null || a.Value is null) throw new ArgumentException("unignore --path PROJECT_PATH --value VALUE");
        var s = SettingsStore.Load();
        s.Unignore(a.Path, a.Value);
        SettingsStore.Save(s);
        return Ignored(o);
    }

    private static int Ignored(TextWriter o)
    {
        var s = SettingsStore.Load();
        foreach (var (p, values) in s.Ignored)
            foreach (var v in values) o.WriteLine($"IGNORED path={Esc(p)} | value={Esc(v)}");
        o.WriteLine($"END | count={s.Ignored.Sum(k => k.Value.Count)}");
        return 0;
    }
}

public sealed class JsonReport
{
    public string Command { get; set; } = "";
    public string Version { get; set; } = "";
    public string Root { get; set; } = "";
    public double Seconds { get; set; }
    public int Exit { get; set; }
    public List<JsonProject> Projects { get; set; } = [];
    public List<CliApp.FixReport>? Fixes { get; set; }
}

public sealed class JsonProject
{
    public string Name { get; set; } = "";
    public string Path { get; set; } = "";
    public bool IsGit { get; set; }
    public string? Branch { get; set; }
    public string? GitHub { get; set; }
    public bool Uncommitted { get; set; }
    public int UnpushedCommits { get; set; }
    public int RemoteOnlyCommits { get; set; }
    public List<string> Notes { get; set; } = [];
    public List<JsonFinding> Findings { get; set; } = [];
}

public sealed class JsonFinding
{
    public string Id { get; set; } = "";
    public string Severity { get; set; } = "";
    public string Category { get; set; } = "";
    public string Value { get; set; } = "";
    public string Path { get; set; } = "";
    public List<int> Lines { get; set; } = [];
    public List<string> Where { get; set; } = [];
    public string State { get; set; } = "";
    public bool CanFix { get; set; }
    public bool OnlyOnRemote { get; set; }
    public bool NeedsHistory { get; set; }
    public string? Fix { get; set; }
    public string? Replacement { get; set; }
    public string? Context { get; set; }
    public string Why { get; set; } = "";
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(JsonReport))]
internal sealed partial class CliJsonContext : JsonSerializerContext;
