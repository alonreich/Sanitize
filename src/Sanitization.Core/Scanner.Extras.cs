using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;

namespace Sanitization.Core;

/// <summary>Extra passes: screenshots (OCR), build output, .git metadata, tags, commit identities, infrastructure dumps, bundles, .gz.</summary>
public sealed partial class Scanner
{
    private const string BundleWhy = "A git bundle is a full copy of a repo's history, including everything you removed later. Delete it (or keep it off any share / zip).";
    private const string LogWhy = "Logs and test results record machine paths, user and PC names. They are build output and don't belong in git.";
    private const string BuildWhy = "Build folders (bin, obj, TestResults) record your user profile path or PC name. They're rebuilt on the next build, so deleting them is safe.";
    private const string InfraWhy = "Many internal addresses or server names in one file: this looks like a dump of real infrastructure (yours or a customer's).";

    internal static readonly HashSet<string> BuildDirs = new(StringComparer.OrdinalIgnoreCase) { "bin", "obj", "TestResults" };

    private static readonly HashSet<string> BotHandles = new(StringComparer.OrdinalIgnoreCase)
    {
        "web-flow", "actions-user", "github-actions", "dependabot", "renovate", "copilot", "claude", "noreply", "ghost",
    };

    private static readonly HashSet<string> InfraNoise = new(StringComparer.OrdinalIgnoreCase)
    {
        "windows", "azure", "azureedge", "azurewebsites", "cloudfront", "cloudapp", "akamai", "akamaiedge", "akamaihd", "googleapis", "gstatic", "googleusercontent",
        "office", "office365", "live", "msftauth", "windowsupdate", "visualstudio", "msedge", "bing", "skype", "outlook", "sharepoint", "fastly", "jsdelivr",
        "unpkg", "githubusercontent", "githubassets", "doubleclick", "gvt1", "msauth", "msecnd", "azurefd", "trafficmanager", "core", "blob",
    };

    private static readonly HashSet<string> CommonTlds = new(StringComparer.Ordinal)
    {
        "com", "net", "org", "edu", "gov", "mil", "int", "info", "biz", "io", "app", "dev", "cloud", "tech", "online", "site", "local", "lan", "corp",
        "internal", "intranet", "localdomain", "home", "arpa",
    };

    private static bool IsOwnMapFile(string rel) => Path.GetFileName(rel).Contains("sanitize-map", StringComparison.OrdinalIgnoreCase);

    private static bool IsGitBundle(string full)
    {
        try
        {
            using var fs = File.OpenRead(full);
            var head = new byte[16];
            var n = fs.Read(head, 0, head.Length);
            var s = Encoding.ASCII.GetString(head, 0, n);
            return s.StartsWith("# v2 git bundle", StringComparison.Ordinal) || s.StartsWith("# v3 git bundle", StringComparison.Ordinal);
        }
        catch { return false; }
    }

    internal static bool IsExecutable(ReadOnlySpan<byte> d) =>
        d.Length > 4 && (d[0] == 0x4D && d[1] == 0x5A || d[0] == 0x7F && d[1] == 0x45 && d[2] == 0x4C && d[3] == 0x46
                         || d[0] == 0xCF && d[1] == 0xFA && d[2] == 0xED && d[3] == 0xFE || d[0] == 0xFE && d[1] == 0xED && d[2] == 0xFA && d[3] == 0xCF);

    /// <summary>A .gz that holds a program (DLL / .so / .dylib) is unpacked and checked like any binary instead of being listed as "can't look inside".</summary>
    private bool CheckGzip(string full, string rel, FileState state)
    {
        byte[] inner;
        try
        {
            using var gz = new GZipStream(File.OpenRead(full), CompressionMode.Decompress);
            using var ms = new MemoryStream();
            var buf = new byte[81920];
            int n;
            while ((n = gz.Read(buf, 0, buf.Length)) > 0)
            {
                ms.Write(buf, 0, n);
                if (ms.Length > 4 * MaxBytes) return false;
            }
            inner = ms.ToArray();
        }
        catch { return false; }
        if (!IsExecutable(inner)) return false;
        var kinds = rules.ScanBinary(inner);
        if (kinds.Count > 0)
            AddWholeFile(rel, state, "Compiled file contains your PC info", Severity.High,
                "This packed binary has your " + string.Join(", ", kinds.Select(k => k.Category.ToLowerInvariant())) + " baked in.", inTree: true);
        return true;
    }

    private static bool IsPrivateLan(string ip)
    {
        var o = ip.Split('.').Select(int.Parse).ToArray();
        if (o[3] is 0 or 255) return false;
        return o[0] == 10 || o[0] == 172 && o[1] is >= 16 and <= 31 || o[0] == 192 && o[1] == 168;
    }

    private static (string Domain, string Label)? RegistrableDomain(string host)
    {
        var l = host.Split('.');
        if (l.Length < 2) return null;
        var take = l.Length >= 3 && l[^1].Length == 2 && l[^2] is "co" or "com" or "org" or "net" or "ac" or "gov" or "edu" ? 3 : 2;
        if (l.Length < take) return null;
        return (string.Join('.', l[^take..]), l[^take]);
    }

    private void CheckInfrastructureDump(string text, string rel, FileState state, bool inTree, bool isLocal, bool isRemote)
    {
        if (text.Length < 200 || rel.Length > 0 && Patterns.VendorPath().IsMatch(rel)) return;
        var ips = new HashSet<string>(StringComparer.Ordinal);
        foreach (Match m in Patterns.IPv4().Matches(text))
            if (IsPrivateLan(m.Groups[1].Value)) ips.Add(m.Groups[1].Value);
        var byDomain = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        var code = Heuristics.IsCodeFile(rel);
        foreach (Match m in Patterns.MultiLabelHost().Matches(text))
        {
            var raw = m.Groups[1].Value;
            var h = raw.ToLowerInvariant();
            var tld = h[(h.LastIndexOf('.') + 1)..];
            // Server names are lower-case with a real top-level domain; code like System.Windows.Media or this.state.value is not.
            if (raw != h || !(tld.Length == 2 || CommonTlds.Contains(tld)) || code && !Heuristics.InsideStringLiteral(text, m.Index)) continue;
            if (Heuristics.IsSafeHost(h) || Heuristics.FileExtensionTlds.Contains(tld)) continue;
            if (RegistrableDomain(h) is not { } d || OrgTerms.Brands.Contains(d.Label) || InfraNoise.Contains(d.Label)) continue;
            if (!byDomain.TryGetValue(d.Domain, out var set)) byDomain[d.Domain] = set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            set.Add(h);
        }
        var hosts = byDomain.Where(kv => kv.Value.Count >= 8).OrderByDescending(kv => kv.Value.Count).ToList();
        if (ips.Count < 10 && hosts.Count == 0) return;
        var sample = new List<string>();
        if (ips.Count >= 10) sample.Add($"{ips.Count} internal IPs (e.g. {string.Join(", ", ips.Take(3))})");
        foreach (var (domain, set) in hosts.Take(2)) sample.Add($"{set.Count} servers at {domain} (e.g. {string.Join(", ", set.Take(2))})");
        var sev = rel.Length > 0 && Patterns.TestPath().IsMatch(rel) ? Severity.Low : Severity.High;
        var f = AddWholeFile(rel, state, "Captured network / customer data", sev, InfraWhy, inTree);
        lock (f) f.Snippet ??= string.Join("; ", sample);
        if (!inTree) MarkHistory(f, isLocal, isRemote);
    }

    /// <summary>Real bytes of a Git LFS pointer, when the object is in the local LFS store.</summary>
    private byte[]? LfsObject(byte[] data)
    {
        if (data.Length > 400 || !Encoding.ASCII.GetString(data).StartsWith("version https://git-lfs.github.com/spec/v1", StringComparison.Ordinal)) return null;
        var m = Regex.Match(Encoding.ASCII.GetString(data), @"oid sha256:([0-9a-f]{64})");
        if (!m.Success) return null;
        var oid = m.Groups[1].Value;
        var path = Path.Combine(_p.Path, ".git", "lfs", "objects", oid[..2], oid[2..4], oid);
        try { return File.Exists(path) && new FileInfo(path).Length <= ImageText.MaxBytes ? File.ReadAllBytes(path) : null; }
        catch { return null; }
    }

    private void AddPictureText(string text, string rel, FileState state, bool inTree, bool isLocal, bool isRemote)
    {
        var values = rules.ScanText(text, "").Where(h => h.Severity <= Severity.Medium).Select(h => h.Value).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (values.Count == 0) return;
        var f = AddWholeFile(rel, state, "Picture shows personal data", Severity.High,
            "Text inside this picture (read with Windows OCR) shows personal data. The pixels can't be edited automatically: replace or crop the image.", inTree);
        lock (f) f.Snippet ??= "shows: " + string.Join(", ", values.Take(5));
        if (!inTree) MarkHistory(f, isLocal, isRemote);
    }

    private async Task ScanImagesAsync(List<(string Rel, FileState State)> files, IProgress<(string, int, int)>? progress, CancellationToken ct)
    {
        var images = files.Where(f => ImageText.Extensions.Contains(Path.GetExtension(f.Rel))).ToList();
        if (images.Count == 0 || !ImageText.Available) return;
        var done = 0;
        await Parallel.ForEachAsync(images, new ParallelOptions { CancellationToken = ct, MaxDegreeOfParallelism = 2 }, async (img, c) =>
        {
            byte[] data;
            try
            {
                var full = Path.Combine(_p.Path, img.Rel.Replace('/', '\\'));
                if (new FileInfo(full).Length > ImageText.MaxBytes) return;
                data = await File.ReadAllBytesAsync(full, c);
            }
            catch { return; }
            data = LfsObject(data) ?? data;
            if (await ImageText.ReadAsync(data, c) is { } text) AddPictureText(text, img.Rel, img.State, inTree: true, false, false);
            var n = Interlocked.Increment(ref done);
            if (n % 10 == 0 || n == images.Count) progress?.Report(("Pictures", n, images.Count));
        });
    }

    private static IEnumerable<string> FindBuildDirs(string root, string rel, int depth)
    {
        if (depth > 8) yield break;
        foreach (var sub in ProjectDiscovery.SafeDirs(Path.Combine(root, rel)))
        {
            var name = Path.GetFileName(sub);
            var subRel = rel.Length == 0 ? name : rel + "/" + name;
            if (name is ".git" or "node_modules" or "packages" or ".nuget" || depth > 0 && Git.IsRepo(sub)) continue;
            if (BuildDirs.Contains(name)) { yield return subRel; continue; }
            foreach (var d in FindBuildDirs(root, subRel, depth + 1)) yield return d;
        }
    }

    private static int Priority(string path) => Path.GetExtension(path).ToLowerInvariant() switch
    {
        ".json" or ".props" or ".targets" or ".cache" or ".txt" or ".xml" or ".config" or ".trx" or ".log" or ".editorconfig" => 0,
        ".pdb" or ".dll" or ".exe" => 2,
        _ => 1,
    };

    /// <summary>bin / obj / TestResults are skipped by the main pass. Here they are checked for your identity only, and reported as one row per project.</summary>
    private async Task ScanBuildOutputAsync(CancellationToken ct)
    {
        if (_p.TopLevelOnly) return;
        var hitDirs = new List<string>();
        var kinds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        long budget = 400L * 1024 * 1024;
        foreach (var dir in FindBuildDirs(_p.Path, "", 0))
        {
            if (budget <= 0) break;
            if (_p.IsGit && (await Git.TryOutAsync(_p.Path, ct, "ls-files", "-c", "--", dir)).Trim().Length > 0) continue;
            IEnumerable<string> all;
            try { all = Directory.EnumerateFiles(Path.Combine(_p.Path, dir.Replace('/', '\\')), "*", SearchOption.AllDirectories).OrderBy(Priority).ToList(); }
            catch { continue; }
            foreach (var file in all)
            {
                ct.ThrowIfCancellationRequested();
                byte[] data;
                try
                {
                    var len = new FileInfo(file).Length;
                    if (len > 5 * 1024 * 1024) continue;
                    if ((budget -= len) <= 0) break;
                    data = await File.ReadAllBytesAsync(file, ct);
                }
                catch { continue; }
                var found = rules.ScanBinary(data);
                if (found.Count == 0) continue;
                hitDirs.Add(dir);
                foreach (var k in found) kinds.Add(k.Category.ToLowerInvariant());
                break;
            }
        }
        if (hitDirs.Count == 0) return;
        var f = AddWholeFile(hitDirs[0], _p.IsGit ? FileState.Ignored : FileState.NotGit, "Build output contains your PC info", Severity.Medium, BuildWhy, inTree: true);
        lock (f)
        {
            foreach (var d in hitDirs) if (!f.Folders.Contains(d)) f.Folders.Add(d);
            f.Snippet ??= $"{hitDirs.Count} folder(s) contain your {string.Join(", ", kinds)}: {string.Join(", ", hitDirs.Take(4))}{(hitDirs.Count > 4 ? ", …" : "")}";
        }
    }

    /// <summary>Things inside .git that hold identity: the repo's own user.name / user.email, stale worktree links, lost-found dumps, stashes.</summary>
    private async Task ScanGitMetadataAsync(CancellationToken ct)
    {
        foreach (var (key, replacement) in new[] { ("user.name", "Dev User"), ("user.email", "dev@example.com") })
        {
            var v = (await Git.TryOutAsync(_p.Path, ct, "config", "--local", "--get", key)).Trim();
            if (v.Length == 0 || v.Equals(replacement, StringComparison.OrdinalIgnoreCase) || rules.IsIgnored(v)) continue;
            if (key == "user.email" ? Heuristics.IsSafeEmail(v) || !v.Contains('@') : IdentityText.IsPlaceholder(v) || BotNames.Contains(v)) continue;
            _findings.TryAdd($"{(int)FindingKind.GitConfig}|.git/config|{key}", new Finding
            {
                ProjectPath = _p.Path, Kind = FindingKind.GitConfig, Severity = Severity.Medium, Category = "Your name / e-mail in this repo's git settings",
                Why = "Every new commit made in this repo will carry it.", Value = v, RelativePath = ".git/config", ConfigKey = key,
                SuggestedReplacement = replacement, Replacement = replacement, InWorkingTree = true, FileState = FileState.Ignored,
            });
        }
        var gitDir = (await Git.TryOutAsync(_p.Path, ct, "rev-parse", "--absolute-git-dir")).Trim();
        if (gitDir.Length == 0 || !Directory.Exists(gitDir)) return;
        foreach (var wt in ProjectDiscovery.SafeDirs(Path.Combine(gitDir, "worktrees")))
        {
            string target;
            try { target = File.ReadAllText(Path.Combine(wt, "gitdir")).Trim(); }
            catch { continue; }
            if (rules.ScanText(target, "").All(h => h.Severity > Severity.High) && !target.Contains(@"\Users\" + rules.Identity.UserName, StringComparison.OrdinalIgnoreCase)
                && !target.Contains("/Users/" + rules.Identity.UserName, StringComparison.OrdinalIgnoreCase)) continue;
            var name = Path.GetFileName(wt);
            var folder = Path.GetDirectoryName(target.Replace('/', '\\')) ?? "";
            _findings.TryAdd($"{(int)FindingKind.GitConfig}|.git/worktrees/{name}|{target}", new Finding
            {
                ProjectPath = _p.Path, Kind = FindingKind.GitConfig, Severity = Severity.Low, Category = "Git worktree link with your user path",
                Why = "git remembers where an extra worktree lives; the path shows your user name.", Value = target, RelativePath = ".git/worktrees/" + name,
                ConfigKey = "worktree:" + folder, Replacement = Directory.Exists(folder) ? null : "prune", InWorkingTree = true, FileState = FileState.Ignored,
            });
        }
        var lostFound = Path.Combine(gitDir, "lost-found");
        if (Directory.Exists(lostFound))
        {
            var identity = false;
            try
            {
                foreach (var file in Directory.EnumerateFiles(lostFound, "*", SearchOption.AllDirectories))
                    if (new FileInfo(file).Length <= MaxBytes && rules.ScanBinary(await File.ReadAllBytesAsync(file, ct)).Count > 0) { identity = true; break; }
            }
            catch { }
            var rel = Path.GetRelativePath(_p.Path, lostFound).Replace('\\', '/');
            var f = AddWholeFile(rel, FileState.Ignored, "Recovered old files (.git/lost-found)", identity ? Severity.Medium : Severity.Low,
                "Left behind by 'git fsck --lost-found': loose copies of old file versions. Delete it unless you are recovering something.", inTree: true);
            lock (f) if (!f.Folders.Contains(rel)) f.Folders.Add(rel);
        }
        if ((await Git.RunAsync(_p.Path, ct, "rev-parse", "-q", "--verify", "refs/stash")).Ok)
            lock (_lock) _p.Notes.Add("This repo has stashed changes. They are scanned, but a history fix can't rewrite the stash: apply or drop it (git stash list).");
    }

    private async Task ScanTagsAsync(CancellationToken ct)
    {
        var raw = await Git.TryOutAsync(_p.Path, ct, "for-each-ref", "refs/tags", "--format=%(objecttype)%00%(refname:short)%00%(taggername)%00%(taggeremail)%00%(contents)%1e");
        foreach (var rec in raw.Split('\x1e'))
        {
            var p = rec.Trim('\n', '\r').Split('\0');
            if (p.Length < 5 || p[0] != "tag") continue;
            AddIdentity(p[2], p[3].Trim('<', '>'), "tag " + p[1], isLocal: true, isRemote: false);
            foreach (var hit in rules.ScanText(p[4], ""))
            {
                var f = GetOrAddText(hit, "");
                lock (f) { f.InLocalHistory = true; f.CommitMessages.Add("tag " + p[1]); f.Snippet ??= "tag message"; }
            }
        }
    }

    /// <summary>One commit / tag identity. E-mails: real ones and GitHub noreply addresses that carry a user name. Names: real-looking full names,
    /// and single-word names that are this owner's known names / handles or the handle in the same commit's noreply address.</summary>
    private void AddIdentity(string name, string email, string where, bool isLocal, bool isRemote)
    {
        name = name.Trim();
        email = email.Trim();
        string? handle = null;
        if (email.Length > 0 && !rules.IsIgnored(email) && !Heuristics.IsSafeEmail(email))
        {
            var gh = IdentityText.GitHubNoreply().Match(email);
            if (gh.Success) handle = gh.Groups[1].Value;
            var report = gh.Success ? !BotHandles.Contains(handle!) && !handle!.Contains("bot", StringComparison.OrdinalIgnoreCase)
                : !email.Contains("noreply", StringComparison.OrdinalIgnoreCase) && !email.Contains("no-reply", StringComparison.OrdinalIgnoreCase);
            if (report)
            {
                var f = _findings.GetOrAdd($"{(int)FindingKind.CommitIdentity}||{email}", _ => new Finding
                {
                    ProjectPath = _p.Path, Kind = FindingKind.CommitIdentity, Severity = Severity.High,
                    Category = gh.Success ? "GitHub user name in commit e-mail" : "Real e-mail as commit author",
                    Why = gh.Success ? "GitHub's private address still shows your GitHub user name on every commit." : "Every commit shows this e-mail publicly on GitHub.",
                    Value = email, SuggestedReplacement = "dev@example.com", Replacement = "dev@example.com",
                });
                lock (f) { f.InLocalHistory |= isLocal; f.OnRemote |= isRemote; f.CommitMessages.Add(where); }
            }
        }
        if (name.Length == 0 || BotNames.Contains(name) || name.Contains("bot", StringComparison.OrdinalIgnoreCase) || rules.IsIgnored(name)) return;
        var known = rules.Identity.FullNames.Contains(name, StringComparer.OrdinalIgnoreCase) || rules.Identity.Handles.Contains(name, StringComparer.OrdinalIgnoreCase)
                    || handle is not null && handle.Equals(name, StringComparison.OrdinalIgnoreCase);
        if (!known && !OfficeText.LooksLikeName(name)) return;
        var n = _findings.GetOrAdd($"{(int)FindingKind.CommitIdentity}||{name}", _ => new Finding
        {
            ProjectPath = _p.Path, Kind = FindingKind.CommitIdentity, Severity = known ? Severity.High : Severity.Medium,
            Category = known && !name.Contains(' ') ? "Your user name as commit author" : "Real name as commit author",
            Why = "Every commit shows this name publicly on GitHub.", Value = name, SuggestedReplacement = "Dev User", Replacement = "Dev User",
        });
        lock (n) { n.InLocalHistory |= isLocal; n.OnRemote |= isRemote; n.CommitMessages.Add(where); }
    }
}
