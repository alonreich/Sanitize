using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;

namespace Sanitization.Core;

public static class ProjectDiscovery
{
    public static readonly HashSet<string> GeneratedDirs = new(StringComparer.OrdinalIgnoreCase)
    {
        ".git", "node_modules", "bin", "obj", ".vs", "packages", "__pycache__", ".venv", "venv", ".gradle", ".idea",
        "bower_components", "TestResults", ".nuget", "dist", "out", "Compiled", ".pytest_cache", ".mypy_cache", "target",
    };

    public static List<ProjectInfo> Discover(string root)
    {
        var list = new List<ProjectInfo>();
        root = Path.GetFullPath(root);
        if (Git.IsRepo(root))
        {
            list.Add(new ProjectInfo { Name = Path.GetFileName(root.TrimEnd('\\')), Path = root, IsGit = true });
            return list;
        }
        foreach (var dir in SafeDirs(root).OrderBy(d => d, StringComparer.OrdinalIgnoreCase))
        {
            var name = Path.GetFileName(dir);
            if (name.StartsWith('.') || GeneratedDirs.Contains(name)) continue;
            var isGit = Git.IsRepo(dir);
            list.Add(new ProjectInfo { Name = name, Path = dir, IsGit = isGit });
            if (!isGit) FindNested(dir, name, list, 1);
        }
        if (SafeFiles(root).Any(f => !Path.GetFileName(f).StartsWith('.')))
            list.Add(new ProjectInfo { Name = "(loose files in the scan folder)", Path = root, TopLevelOnly = true });
        return list;
    }

    private static void FindNested(string dir, string prefix, List<ProjectInfo> list, int depth)
    {
        if (depth > 4) return;
        foreach (var sub in SafeDirs(dir))
        {
            var name = Path.GetFileName(sub);
            if (GeneratedDirs.Contains(name)) continue;
            if (Git.IsRepo(sub)) list.Add(new ProjectInfo { Name = $"{prefix} / {name}", Path = sub, IsGit = true });
            else FindNested(sub, $"{prefix} / {name}", list, depth + 1);
        }
    }

    internal static IEnumerable<string> SafeDirs(string d)
    {
        try { return Directory.EnumerateDirectories(d).Where(x => (new DirectoryInfo(x).Attributes & FileAttributes.ReparsePoint) == 0).ToList(); }
        catch { return []; }
    }

    internal static IEnumerable<string> SafeFiles(string d)
    {
        try { return Directory.EnumerateFiles(d).ToList(); }
        catch { return []; }
    }
}

public sealed class Scanner(RuleSet rules)
{
    public const long MaxBytes = 25L * 1024 * 1024;
    private readonly ConcurrentDictionary<string, Finding> _findings = new(StringComparer.Ordinal);
    private ProjectInfo _p = null!;
    private ScanContext _ctx = null!;
    private readonly object _lock = new();
    private readonly ConcurrentBag<(string Rel, FileState State)> _textFiles = [];

    public static async Task<ProjectScanResult> ScanAsync(ProjectInfo project, MachineIdentity id, IReadOnlyList<PrivateTerm> terms,
        IEnumerable<string> ignoredValues, IProgress<(string Phase, int Done, int Total)>? progress, CancellationToken ct, ScanContext? context = null)
    {
        var sw = Stopwatch.StartNew();
        context ??= ScanContext.Ephemeral();
        var ignored = ignoredValues.ToList();
        var localEmail = project.IsGit ? (await Git.TryOutAsync(project.Path, ct, "config", "--local", "--get", "user.email")).Trim() : "";
        var rules = new RuleSet(id, terms, localEmail.Length > 0 ? [localEmail] : [], ignored, context.Orgs.All);
        var scanner = new Scanner(rules) { _p = project, _ctx = context };
        await scanner.RunAsync(progress, ct);
        await scanner.PostPassAsync(ignored, ct);
        var list = Condense(project, scanner._findings.Values.ToList());
        foreach (var f in list) FixPlanner.Plan(project, f);
        return new ProjectScanResult { Project = project, Findings = FindingOrdering.Sort(list).ToList(), Duration = sw.Elapsed };
    }

    public const int CondenseThreshold = 15;
    private const string PhotoWhy = "The photo's hidden EXIF data says exactly where it was taken (often your home).";

    internal static List<Finding> Condense(ProjectInfo p, List<Finding> findings)
    {
        var result = new List<Finding>();
        foreach (var g in findings.GroupBy(f => (f.Kind, f.Severity, f.Category, f.RelativePath)))
        {
            if (g.Key.Kind != FindingKind.TextValue || g.Key.Severity != Severity.Low || g.Key.RelativePath.Length == 0 || g.Count() < CondenseThreshold)
            {
                result.AddRange(g);
                continue;
            }
            var items = g.ToList();
            var first = items[0];
            var sample = string.Join(", ", items.Select(i => i.Value).Distinct().Take(6));
            var summary = new Finding
            {
                ProjectPath = p.Path, Kind = FindingKind.WholeFile, Severity = Severity.Low, Category = $"{g.Key.Category} × {items.Count}",
                Why = "Too many to list one by one (probably generated or sample data). Open the file and check it.",
                Value = sample + (items.Count > 6 ? ", …" : ""), RelativePath = g.Key.RelativePath, Inspectable = false,
                FileState = first.FileState, InWorkingTree = items.Any(i => i.InWorkingTree), InLocalHistory = items.Any(i => i.InLocalHistory),
                OnRemote = items.Any(i => i.OnRemote), HistoryVersions = items.Max(i => i.HistoryVersions),
            };
            summary.Lines.AddRange(items.SelectMany(i => i.Lines).Distinct().Order().Take(10));
            result.Add(summary);
        }
        return result;
    }

    private async Task RunAsync(IProgress<(string, int, int)>? progress, CancellationToken ct)
    {
        if (_p.IsGit) await ReadProjectStateAsync(ct);
        var files = await ListWorkingTreeAsync(ct);
        _p.FilesScanned = files.Count;
        var done = 0;
        await Parallel.ForEachAsync(files, new ParallelOptions { CancellationToken = ct, MaxDegreeOfParallelism = Math.Max(2, Environment.ProcessorCount) }, (f, c) =>
        {
            ScanWorkingFile(f.Rel, f.State);
            var n = Interlocked.Increment(ref done);
            if (n % 25 == 0 || n == files.Count) progress?.Report(("Files", n, files.Count));
            return ValueTask.CompletedTask;
        });
        if (!_p.IsGit) return;
        await ScanRemotesAsync(ct);
        await ScanCommitsAsync(ct);
        await ScanHistoryAsync(progress, ct);
    }

    private async Task ReadProjectStateAsync(CancellationToken ct)
    {
        _p.HasUncommittedChanges = (await Git.TryOutAsync(_p.Path, ct, "status", "--porcelain", "--untracked-files=no")).Trim().Length > 0;
        _p.Branch = (await Git.TryOutAsync(_p.Path, ct, "branch", "--show-current")).Trim();
        _p.OriginUrl = (await Git.TryOutAsync(_p.Path, ct, "remote", "get-url", "origin")).Trim();
        var m = Patterns.GitHubRemote().Match(System.Text.RegularExpressions.Regex.Replace(_p.OriginUrl, @"://[^/@\s]+@", "://"));
        _p.GitHub = m.Success ? new GitHubRepoRef(m.Groups[1].Value, m.Groups[2].Value) : null;
        int.TryParse((await Git.TryOutAsync(_p.Path, ct, "rev-list", "--branches", "--tags", "--count")).Trim(), out var local);
        int.TryParse((await Git.TryOutAsync(_p.Path, ct, "rev-list", "--remotes", "--not", "--branches", "--tags", "--count")).Trim(), out var remoteOnly);
        int.TryParse((await Git.TryOutAsync(_p.Path, ct, "rev-list", "--branches", "--not", "--remotes", "--count")).Trim(), out var localOnly);
        _p.LocalCommits = local;
        _p.RemoteOnlyCommits = remoteOnly;
        _p.LocalOnlyCommits = localOnly;
    }

    private async Task<List<(string Rel, FileState State)>> ListWorkingTreeAsync(CancellationToken ct)
    {
        var result = new List<(string, FileState)>();
        if (_p.TopLevelOnly)
        {
            foreach (var f in ProjectDiscovery.SafeFiles(_p.Path)) result.Add((Path.GetFileName(f), FileState.NotGit));
            return result;
        }
        if (!_p.IsGit)
        {
            Walk(_p.Path, "", FileState.NotGit, result, nestedReposAreProjects: true);
            return result;
        }
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var rel in Git.SplitZ(await Git.TryOutAsync(_p.Path, ct, "ls-files", "-z", "-c")))
            if (seen.Add(rel)) result.Add((rel, FileState.Tracked));
        foreach (var rel in Git.SplitZ(await Git.TryOutAsync(_p.Path, ct, "ls-files", "-z", "-o", "--exclude-standard")))
            if (!InGeneratedDir(rel) && seen.Add(rel)) result.Add((rel, FileState.Untracked));
        foreach (var rel in Git.SplitZ(await Git.TryOutAsync(_p.Path, ct, "ls-files", "-z", "-o", "-i", "--exclude-standard", "--directory")))
        {
            if (InGeneratedDir(rel)) continue;
            if (rel.EndsWith('/'))
            {
                var name = rel.TrimEnd('/').Split('/')[^1];
                if (!ProjectDiscovery.GeneratedDirs.Contains(name)) Walk(Path.Combine(_p.Path, rel.TrimEnd('/')), rel.TrimEnd('/'), FileState.Ignored, result, false);
            }
            else if (seen.Add(rel)) result.Add((rel, FileState.Ignored));
        }
        return result;
    }

    private static bool InGeneratedDir(string rel)
    {
        var parts = rel.TrimEnd('/').Split('/');
        for (var i = 0; i < parts.Length - (rel.EndsWith('/') ? 0 : 1); i++)
            if (ProjectDiscovery.GeneratedDirs.Contains(parts[i])) return true;
        return false;
    }

    private static void Walk(string dir, string relDir, FileState state, List<(string, FileState)> output, bool nestedReposAreProjects)
    {
        foreach (var f in ProjectDiscovery.SafeFiles(dir))
            output.Add((relDir.Length == 0 ? Path.GetFileName(f) : relDir + "/" + Path.GetFileName(f), state));
        foreach (var sub in ProjectDiscovery.SafeDirs(dir))
        {
            var name = Path.GetFileName(sub);
            if (ProjectDiscovery.GeneratedDirs.Contains(name)) continue;
            if (nestedReposAreProjects && Git.IsRepo(sub)) continue;
            Walk(sub, relDir.Length == 0 ? name : relDir + "/" + name, state, output, nestedReposAreProjects);
        }
    }

    private void ScanWorkingFile(string rel, FileState state)
    {
        var full = Path.Combine(_p.Path, rel.Replace('/', '\\'));
        FileInfo fi;
        try { fi = new FileInfo(full); if (!fi.Exists) return; }
        catch { return; }

        if (Patterns.SensitiveFileName().IsMatch(rel))
        {
            AddWholeFile(rel, state, "Key, password or dump file", Severity.Critical,
                "Private keys, certificates, password vaults and memory / network dumps can expose everything.", inTree: true);
            return;
        }
        var ext = Path.GetExtension(rel);
        if (OfficeText.IsOffice(rel) && fi.Length <= MaxBytes)
        {
            byte[] doc;
            try { doc = File.ReadAllBytes(full); }
            catch { doc = []; }
            if (ScanOffice(doc, rel, state, inTree: true, isLocal: false, isRemote: false)) return;
        }
        if (TextCodec.NotInspectableExtensions.Contains(ext))
        {
            if (state == FileState.Tracked)
                AddWholeFile(rel, state, "Archive / document (can't look inside)", Severity.Low,
                    "Compressed files and documents can't be checked automatically. Open it and check it yourself.", inTree: true, inspectable: false);
            return;
        }
        if (fi.Length > MaxBytes)
        {
            if (state == FileState.Tracked)
                AddWholeFile(rel, state, "File too large to scan", Severity.Low, "Over 25 MB. Check it yourself.", inTree: true, inspectable: false);
            return;
        }
        if (PhotoLocation.Extensions.Contains(ext))
        {
            try
            {
                var img = File.ReadAllBytes(full);
                if (PhotoLocation.HasGps(img))
                    AddWholeFile(rel, state, "Photo with GPS location", Severity.High, PhotoWhy, inTree: true, photo: true);
            }
            catch { }
            return;
        }
        if (TextCodec.IsBinaryExtension(rel) && state != FileState.Tracked) return;
        byte[] data;
        try { data = File.ReadAllBytes(full); }
        catch (Exception e) { lock (_lock) _p.Notes.Add($"Can't read {rel}: {e.Message}"); return; }
        var (text, _) = TextCodec.Decode(data);
        if (text is null)
        {
            if (state != FileState.Tracked) return;
            var kinds = rules.ScanBinary(data);
            if (kinds.Count > 0)
                AddWholeFile(rel, state, "Compiled file contains your PC info", Severity.High,
                    "This binary has your " + string.Join(", ", kinds.Select(k => k.Category.ToLowerInvariant())) + " baked in (e.g. a build path).", inTree: true);
            return;
        }
        _textFiles.Add((rel, state));
        foreach (var hit in rules.ScanText(text, rel))
        {
            var f = GetOrAddText(hit, rel);
            lock (f)
            {
                f.InWorkingTree = true;
                f.FileState = state;
                var line = 1;
                for (var i = 0; i < hit.Index; i++) if (text[i] == '\n') line++;
                if (!f.Lines.Contains(line)) f.Lines.Add(line);
                f.Snippet ??= Snippet(text, hit.Index, hit.Value.Length);
            }
        }
    }

    private static string Snippet(string text, int index, int length)
    {
        var start = text.LastIndexOf('\n', Math.Max(0, index - 1)) + 1;
        var end = text.IndexOf('\n', index + length);
        if (end < 0) end = text.Length;
        var line = text[start..end].Trim();
        if (line.Length > 220)
        {
            var rel = Math.Max(0, index - start - 80);
            line = (rel > 0 ? "…" : "") + text.Substring(start + rel, Math.Min(220, end - start - rel)).Trim() + "…";
        }
        return line;
    }

    private string? Placeholder(Hit hit)
    {
        var kind = hit.Rule.PlaceholderKind;
        if (kind is null || hit.Replacement is null) return hit.Replacement;
        switch (kind)
        {
            case "mac":
                return PlaceholderMap.FormatMac(_ctx.Placeholders.For(kind, hit.Value), hit.Value);
            case "tenant":
                var dot = hit.Value.IndexOf('.');
                return dot <= 0 ? hit.Replacement : _ctx.Placeholders.For(kind, hit.Value[..dot]) + hit.Value[dot..];
            case "id":
                return _ctx.Placeholders.For(Guid.TryParse(hit.Value, out _) ? "guid" : "id", hit.Value);
            default:
                return _ctx.Placeholders.For(kind, hit.Value);
        }
    }

    private Finding GetOrAddText(Hit hit, string rel, bool inDocument = false)
    {
        var key = $"{(int)FindingKind.TextValue}|{rel}|{hit.Value}";
        var f = _findings.GetOrAdd(key, _ =>
        {
            var repl = Placeholder(hit);
            return new Finding
            {
                ProjectPath = _p.Path, Kind = FindingKind.TextValue, Severity = hit.Severity, Category = hit.Rule.Category, Why = hit.Rule.Why,
                Value = hit.Value, SuggestedReplacement = repl, Replacement = repl, RelativePath = rel, InsideDocument = inDocument,
                FileState = _p.IsGit ? FileState.None : FileState.NotGit,
            };
        });
        lock (f) if (hit.Severity < f.Severity) f.Severity = hit.Severity;
        return f;
    }

    private bool ScanOffice(byte[] data, string rel, FileState state, bool inTree, bool isLocal, bool isRemote)
    {
        if (OfficeText.Extract(data) is not { } doc) return false;
        var hits = rules.ScanText(doc.Text, rel);
        foreach (var hit in hits)
        {
            var f = GetOrAddText(hit, rel, inDocument: true);
            lock (f)
            {
                if (inTree) { f.InWorkingTree = true; f.FileState = state; }
                f.Snippet ??= Snippet(doc.Text, hit.Index, hit.Value.Length);
            }
            if (!inTree) MarkHistory(f, isLocal, isRemote);
        }
        foreach (var author in doc.Authors.Where(a => !rules.IsIgnored(a)))
        {
            var key = $"{(int)FindingKind.TextValue}|{rel}|{author}";
            var f = _findings.GetOrAdd(key, _ => new Finding
            {
                ProjectPath = _p.Path, Kind = FindingKind.TextValue, Severity = Severity.Medium, Category = "Document author / company",
                Why = "The document's hidden properties name a person or company.", Value = author, RelativePath = rel, InsideDocument = true,
                Snippet = "document properties", FileState = _p.IsGit ? FileState.None : FileState.NotGit,
            });
            lock (f) if (inTree) { f.InWorkingTree = true; f.FileState = state; }
            if (!inTree) MarkHistory(f, isLocal, isRemote);
        }
        return true;
    }

    internal static readonly HashSet<string> BotNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "Dev User", "John Doe", "Jane Doe", "GitHub", "GitHub Actions", "GitHub Enterprise", "Web Flow", "Dependabot", "Renovate Bot",
        "Copilot", "Claude", "Tester", "Test User", "Build Agent", "Azure Pipelines", "Gitlab Runner",
    };

    private async Task PostPassAsync(List<string> ignored, CancellationToken ct)
    {
        var learned = new List<(string Label, string Domain)>();
        foreach (var f in _findings.Values.Where(f => f.Kind == FindingKind.TextValue && f.Category == "E-mail address" && f.Severity <= Severity.Medium))
            if (OrgTerms.FromEmail(f.Value) is { } org && _ctx.Orgs.Learn(f.Value)) learned.Add(org);
        var strong = _findings.Values
            .Where(f => f.Kind == FindingKind.TextValue && f.Severity <= Severity.Medium && !f.InsideDocument && f.Value.Length >= 4 && f.Replacement is not null)
            .GroupBy(f => f.Value, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.OrderBy(f => f.Severity).First(), StringComparer.OrdinalIgnoreCase);

        foreach (var f in _findings.Values.Where(f => f.Kind == FindingKind.TextValue && f.Severity == Severity.Low && strong.ContainsKey(f.Value)))
        {
            var src = strong[f.Value];
            lock (f) { f.Severity = src.Severity; f.Propagated = true; f.Replacement = src.Replacement; }
        }

        var orgRules = learned.Select(o => OrgTerms.BuildRule(o.Label, o.Domain)).ToList();
        if (strong.Count == 0 && orgRules.Count == 0) return;
        var valueRx = strong.Count == 0 ? null : new System.Text.RegularExpressions.Regex(
            string.Join("|", strong.Keys.OrderByDescending(k => k.Length).Select(Heuristics.Bounded)),
            System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.CultureInvariant);
        var ignoredSet = new HashSet<string>(ignored, StringComparer.OrdinalIgnoreCase);
        await Parallel.ForEachAsync(_textFiles, new ParallelOptions { CancellationToken = ct, MaxDegreeOfParallelism = Math.Max(2, Environment.ProcessorCount) }, (file, c) =>
        {
            string? text;
            try { text = TextCodec.Decode(File.ReadAllBytes(Path.Combine(_p.Path, file.Rel.Replace('/', '\\')))).Text; }
            catch { return ValueTask.CompletedTask; }
            if (text is null) return ValueTask.CompletedTask;
            if (valueRx is not null)
                foreach (System.Text.RegularExpressions.Match m in valueRx.Matches(text))
                {
                    var src = strong[m.Value];
                    var key = $"{(int)FindingKind.TextValue}|{file.Rel}|{m.Value}";
                    var f = _findings.GetOrAdd(key, _ => new Finding
                    {
                        ProjectPath = _p.Path, Kind = FindingKind.TextValue, Severity = src.Severity, Category = src.Category,
                        Why = src.Why + " (Same value as in " + (src.RelativePath.Length == 0 ? "a commit" : src.RelativePath) + ".)",
                        Value = m.Value, SuggestedReplacement = src.Replacement, Replacement = src.Replacement, RelativePath = file.Rel, Propagated = true,
                        FileState = file.State,
                    });
                    AddLocation(f, text, m.Index, m.Length, file.State);
                }
            foreach (var rule in orgRules)
                foreach (System.Text.RegularExpressions.Match m in rule.Regex.Matches(text))
                {
                    if (ignoredSet.Contains(m.Value)) continue;
                    var f = GetOrAddText(new Hit(rule, m.Value, rule.Replace!(m), m.Index, rule.Severity), file.Rel);
                    AddLocation(f, text, m.Index, m.Length, file.State);
                }
            return ValueTask.CompletedTask;
        });
    }

    private static void AddLocation(Finding f, string text, int index, int length, FileState state)
    {
        lock (f)
        {
            f.InWorkingTree = true;
            f.FileState = state;
            var line = 1;
            for (var i = 0; i < index; i++) if (text[i] == '\n') line++;
            if (!f.Lines.Contains(line)) f.Lines.Add(line);
            f.Snippet ??= Snippet(text, index, length);
        }
    }

    private Finding AddWholeFile(string rel, FileState state, string category, Severity sev, string why, bool inTree, bool inspectable = true, bool photo = false)
    {
        var key = $"{(int)FindingKind.WholeFile}|{rel}|{rel}";
        var f = _findings.GetOrAdd(key, _ => new Finding
        {
            ProjectPath = _p.Path, Kind = FindingKind.WholeFile, Severity = sev, Category = category, Why = why, Value = rel,
            RelativePath = rel, Inspectable = inspectable, FileState = state, PhotoGps = photo,
        });
        lock (f)
        {
            if (inTree) { f.InWorkingTree = true; f.FileState = state; }
            if (sev < f.Severity) f.Severity = sev;
        }
        return f;
    }

    private async Task ScanRemotesAsync(CancellationToken ct)
    {
        foreach (var line in (await Git.TryOutAsync(_p.Path, ct, "remote", "-v")).Split('\n'))
        {
            var parts = line.Split(['\t', ' '], StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 3 || parts[2] != "(fetch)") continue;
            var m = System.Text.RegularExpressions.Regex.Match(parts[1], @"://([^/@\s]+)@");
            if (!m.Success || rules.IsIgnored(parts[1])) continue;
            var key = $"{(int)FindingKind.RemoteUrl}|remote {parts[0]}|{parts[1]}";
            _findings.TryAdd(key, new Finding
            {
                ProjectPath = _p.Path, Kind = FindingKind.RemoteUrl, Severity = Severity.Critical, Category = "Password / token in git remote URL",
                Why = RuleSet.WhySecret, Value = parts[1], RelativePath = $"remote {parts[0]}", RemoteName = parts[0],
                SuggestedReplacement = parts[1].Replace(m.Value, "://"), Replacement = parts[1].Replace(m.Value, "://"),
            });
        }
    }

    private async Task ScanCommitsAsync(CancellationToken ct)
    {
        var local = new HashSet<string>(SplitLines(await Git.TryOutAsync(_p.Path, ct, "rev-list", "--branches", "--tags")), StringComparer.Ordinal);
        var remote = new HashSet<string>(SplitLines(await Git.TryOutAsync(_p.Path, ct, "rev-list", "--remotes")), StringComparer.Ordinal);
        var log = await Git.TryOutAsync(_p.Path, ct, "log", "--branches", "--tags", "--remotes", "--format=%H%x00%an%x00%ae%x00%cn%x00%ce%x00%B%x1e");
        var noreply = rules.Identity.GlobalGitEmail.Contains("noreply", StringComparison.OrdinalIgnoreCase) ? rules.Identity.GlobalGitEmail : "user@example.com";
        foreach (var rec in log.Split('\x1e'))
        {
            var parts = rec.Trim('\n', '\r').Split('\0');
            if (parts.Length < 6) continue;
            var sha = parts[0];
            var isLocal = local.Contains(sha);
            var isRemote = remote.Contains(sha);
            foreach (var email in new[] { parts[2], parts[4] }.Distinct())
            {
                if (email.Length == 0 || email.Contains("noreply", StringComparison.OrdinalIgnoreCase) || rules.IsIgnored(email)) continue;
                var key = $"{(int)FindingKind.CommitIdentity}||{email}";
                var f = _findings.GetOrAdd(key, _ => new Finding
                {
                    ProjectPath = _p.Path, Kind = FindingKind.CommitIdentity, Severity = Severity.High, Category = "Real e-mail as commit author",
                    Why = "Every commit shows this e-mail publicly on GitHub.", Value = email, SuggestedReplacement = noreply, Replacement = noreply,
                });
                lock (f) { f.InLocalHistory |= isLocal; f.OnRemote |= isRemote; f.CommitMessages.Add(sha[..10]); }
            }
            foreach (var name in new[] { parts[1].Trim(), parts[3].Trim() }.Distinct())
            {
                if (!OfficeText.LooksLikeName(name) || BotNames.Contains(name) || name.Contains("bot", StringComparison.OrdinalIgnoreCase) || rules.IsIgnored(name)) continue;
                var key = $"{(int)FindingKind.CommitIdentity}||{name}";
                var f = _findings.GetOrAdd(key, _ => new Finding
                {
                    ProjectPath = _p.Path, Kind = FindingKind.CommitIdentity, Severity = Severity.Medium, Category = "Real name as commit author",
                    Why = "Every commit shows this full name publicly on GitHub.", Value = name, SuggestedReplacement = "Dev User", Replacement = "Dev User",
                });
                lock (f) { f.InLocalHistory |= isLocal; f.OnRemote |= isRemote; f.CommitMessages.Add(sha[..10]); }
            }
            foreach (var hit in rules.ScanText($"{parts[1]}\n{parts[3]}\n{parts[5]}", ""))
            {
                var f = GetOrAddText(hit, "");
                lock (f) { f.InLocalHistory |= isLocal; f.OnRemote |= isRemote; f.CommitMessages.Add(sha[..10]); f.Snippet ??= "commit message"; }
            }
        }
    }

    private static IEnumerable<string> SplitLines(string s) => s.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    private static Dictionary<string, List<string>> ParseObjects(string output)
    {
        var map = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        foreach (var line in output.Split('\n'))
        {
            var sp = line.IndexOf(' ');
            if (sp <= 0) continue;
            var sha = line[..sp];
            var path = line[(sp + 1)..].TrimEnd('\r');
            if (path.Length == 0) continue;
            if (!map.TryGetValue(sha, out var l)) map[sha] = l = [];
            if (!l.Contains(path)) l.Add(path);
        }
        return map;
    }

    private async Task ScanHistoryAsync(IProgress<(string, int, int)>? progress, CancellationToken ct)
    {
        var local = ParseObjects(await Git.TryOutAsync(_p.Path, ct, "rev-list", "--objects", "--branches", "--tags"));
        var remote = ParseObjects(await Git.TryOutAsync(_p.Path, ct, "rev-list", "--objects", "--remotes"));
        var all = new Dictionary<string, List<string>>(local, StringComparer.Ordinal);
        foreach (var (sha, paths) in remote)
            if (all.TryGetValue(sha, out var l)) l.AddRange(paths.Where(p => !l.Contains(p)));
            else all[sha] = paths;
        if (all.Count == 0) return;

        var check = await Git.RunWithInputAsync(_p.Path, Encoding.ASCII.GetBytes(string.Join('\n', all.Keys) + "\n"), ct,
            "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)");
        var blobs = new List<string>();
        foreach (var line in check.StdOut.Split('\n'))
        {
            var parts = line.Trim().Split(' ');
            if (parts.Length < 3 || parts[1] != "blob") continue;
            var sha = parts[0];
            var names = all[sha];
            var isLocal = local.ContainsKey(sha);
            var isRemote = remote.ContainsKey(sha);
            var sensitive = names.Where(n => Patterns.SensitiveFileName().IsMatch(n)).ToList();
            if (sensitive.Count > 0)
            {
                foreach (var n in sensitive) MarkHistory(AddWholeFile(n, FileState.None, "Key, password or dump file", Severity.Critical,
                    "Private keys, certificates, password vaults and memory / network dumps can expose everything.", inTree: false), isLocal, isRemote);
                continue;
            }
            if (long.Parse(parts[2]) > MaxBytes) continue;
            blobs.Add(sha);
        }
        _p.BlobsScanned = blobs.Count;
        var done = 0;
        await foreach (var (sha, data) in Git.CatBlobsAsync(_p.Path, blobs, ct))
        {
            if (++done % 50 == 0 || done == blobs.Count) progress?.Report(("History", done, blobs.Count));
            var names = all[sha];
            var isLocal = local.ContainsKey(sha);
            var isRemote = remote.ContainsKey(sha);
            var preferred = names.FirstOrDefault(n => File.Exists(Path.Combine(_p.Path, n.Replace('/', '\\')))) ?? names[0];
            var (text, _) = TextCodec.Decode(data);
            if (text is null)
            {
                if (names.Any(OfficeText.IsOffice))
                {
                    var docName = names.First(OfficeText.IsOffice);
                    if (ScanOffice(data, docName, FileState.None, inTree: false, isLocal, isRemote)) continue;
                }
                if (PhotoLocation.IsJpeg(data))
                {
                    if (PhotoLocation.HasGps(data))
                        foreach (var n in names)
                            MarkHistory(AddWholeFile(n, FileState.None, "Photo with GPS location", Severity.High, PhotoWhy, inTree: false, photo: true), isLocal, isRemote);
                    continue;
                }
                var kinds = rules.ScanBinary(data);
                if (kinds.Count > 0)
                    foreach (var n in names)
                        MarkHistory(AddWholeFile(n, FileState.None, "Compiled file contains your PC info", Severity.High,
                            "This binary has your " + string.Join(", ", kinds.Select(k => k.Category.ToLowerInvariant())) + " baked in (e.g. a build path).", inTree: false), isLocal, isRemote);
                continue;
            }
            foreach (var hit in rules.ScanText(text, preferred))
            {
                var f = GetOrAddText(hit, preferred);
                MarkHistory(f, isLocal, isRemote);
                lock (f) f.Snippet ??= Snippet(text, hit.Index, hit.Value.Length);
            }
        }
    }

    private static void MarkHistory(Finding f, bool isLocal, bool isRemote)
    {
        lock (f)
        {
            f.InLocalHistory |= isLocal;
            f.OnRemote |= isRemote;
            f.HistoryVersions++;
        }
    }
}

public static class FindingOrdering
{
    public static IEnumerable<Finding> Sort(IEnumerable<Finding> findings) => findings
        .OrderBy(f => f.Severity)
        .ThenBy(f => f.OnlyOnRemote ? 1 : 0)
        .ThenBy(f => f.Category, StringComparer.OrdinalIgnoreCase)
        .ThenBy(f => f.RelativePath, StringComparer.OrdinalIgnoreCase)
        .ThenBy(f => f.Lines.Count > 0 ? f.Lines.Min() : int.MaxValue);

    public static IEnumerable<ProjectScanResult> SortProjects(IEnumerable<ProjectScanResult> results) => results
        .OrderBy(r => r.Findings.Count == 0 ? 99 : (int)r.Findings.Min(f => f.Severity))
        .ThenByDescending(r => r.Findings.Count(f => f.Severity != Severity.Low))
        .ThenBy(r => r.Project.Name, StringComparer.OrdinalIgnoreCase);
}
