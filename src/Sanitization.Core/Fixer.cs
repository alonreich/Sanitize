using System.Security.Cryptography;
using System.Text;

namespace Sanitization.Core;

/// <summary>One "Fix" click. Undo restores files only (kept in memory, never on disk); history rewrites are permanent.</summary>
public sealed class UndoBatch
{
    internal readonly List<(string Path, byte[]? Original, byte[] WrittenHash)> Files = [];
    internal readonly List<(string Repo, string Rel)> Untracked = [];
    internal readonly List<(string Repo, string Remote, string Url)> Remotes = [];
    public string Summary { get; set; } = "";
    public bool IsEmpty => Files.Count == 0 && Untracked.Count == 0 && Remotes.Count == 0;
    public int FileCount => Files.Count;
    public IEnumerable<string> Paths => Files.Select(f => f.Path).Concat(Untracked.Select(u => u.Repo)).Concat(Remotes.Select(r => r.Repo));
}

public sealed class FixOutcome
{
    public required ProjectInfo Project { get; init; }
    public int FilesChanged { get; set; }
    public int ItemsFixed { get; set; }
    public bool HistoryRewritten { get; set; }
    public string? HistoryBlocked { get; set; }
    public List<string> Errors { get; } = [];
}

public static class Fixer
{
    public static async Task<FixOutcome> ApplyAsync(ProjectInfo p, IReadOnlyList<Finding> selected, bool allowHistory, UndoBatch undo,
        IProgress<string>? progress, CancellationToken ct)
    {
        var outcome = new FixOutcome { Project = p };
        var fixable = selected.Where(f => f.CanFix).ToList();
        if (fixable.Count == 0) return outcome;

        // 1. history first (needs a clean repo); it also fixes tracked files through the reset that follows.
        var historyItems = fixable.Where(FixPlanner.TouchesHistory).ToList();
        if (historyItems.Count > 0 && p.IsGit)
        {
            if (!allowHistory) outcome.HistoryBlocked = "You chose to fix files only.";
            else if ((await Git.TryOutAsync(p.Path, ct, "status", "--porcelain", "--untracked-files=no")).Trim().Length > 0)
                outcome.HistoryBlocked = "This repo has uncommitted changes. Commit or stash them, then fix again to clean the history.";
            else
            {
                var replacements = new Dictionary<string, string>(StringComparer.Ordinal);
                var drop = new HashSet<string>(StringComparer.Ordinal);
                var emails = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (var f in historyItems)
                {
                    if (f.Actions.HasFlag(FixActions.RewriteHistory) && f.Replacement is not null) replacements.TryAdd(f.Value, f.Replacement);
                    if (f.Actions.HasFlag(FixActions.DropFromHistory)) drop.Add(f.RelativePath);
                    if (f.Actions.HasFlag(FixActions.RewriteIdentity) && f.Replacement is not null) emails[f.Value] = f.Replacement;
                }
                var keep = new Dictionary<string, byte[]>(StringComparer.Ordinal);
                foreach (var rel in drop)
                {
                    var full = Full(p, rel);
                    if (File.Exists(full)) keep[rel] = await File.ReadAllBytesAsync(full, ct);
                }
                try
                {
                    await HistoryRewriter.RewriteAsync(p.Path, new HistoryRewriter.Plan(replacements, drop, emails), progress, ct);
                    outcome.HistoryRewritten = true;
                    foreach (var (rel, bytes) in keep)
                    {
                        var full = Full(p, rel);
                        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
                        if (!File.Exists(full)) await File.WriteAllBytesAsync(full, bytes, ct);
                    }
                    if (keep.Count > 0) await AddToGitignoreAsync(p, keep.Keys, null, ct);
                }
                catch (Exception e)
                {
                    outcome.Errors.Add("History rewrite failed: " + e.Message);
                    foreach (var (rel, bytes) in keep)
                        if (!File.Exists(Full(p, rel))) await File.WriteAllBytesAsync(Full(p, rel), bytes, ct);
                }
            }
        }

        // 2. text replacements in files (journaled for Undo)
        progress?.Report("Fixing files…");
        foreach (var group in fixable.Where(f => f.Actions.HasFlag(FixActions.ReplaceInFile) && f.Replacement is not null).GroupBy(f => f.RelativePath))
        {
            var full = Full(p, group.Key);
            try
            {
                if (!File.Exists(full)) continue;
                var original = await File.ReadAllBytesAsync(full, ct);
                var map = new Dictionary<string, string>(StringComparer.Ordinal);
                foreach (var f in group) map.TryAdd(f.Value, f.Replacement!);
                var updated = new Replacer(map).Data(original);
                if (ReferenceEquals(updated, original)) continue;
                await AtomicWriteAsync(full, updated, ct);
                undo.Files.Add((full, original, SHA256.HashData(updated)));
                outcome.FilesChanged++;
            }
            catch (Exception e) { outcome.Errors.Add($"{group.Key}: {e.Message}"); }
        }

        // 3. whole files: stop tracking + .gitignore (the file stays on disk)
        if (p.IsGit)
        {
            var tracked = new HashSet<string>(Git.SplitZ(await Git.TryOutAsync(p.Path, ct, "ls-files", "-z", "-c")), StringComparer.Ordinal);
            var toIgnore = new List<string>();
            foreach (var f in fixable.Where(f => f.Kind == FindingKind.WholeFile && (f.Actions & (FixActions.Untrack | FixActions.AddToGitignore)) != 0))
            {
                if (tracked.Contains(f.RelativePath))
                {
                    var r = await Git.RunAsync(p.Path, ct, "rm", "--cached", "-q", "--", f.RelativePath);
                    if (r.Ok) undo.Untracked.Add((p.Path, f.RelativePath));
                    else outcome.Errors.Add($"{f.RelativePath}: {r.StdErr.Trim()}");
                }
                toIgnore.Add(f.RelativePath);
            }
            if (toIgnore.Count > 0) await AddToGitignoreAsync(p, toIgnore, undo, ct);

            // 4. remote URLs
            foreach (var f in fixable.Where(f => f.Kind == FindingKind.RemoteUrl && f.RemoteName is not null && f.Replacement is not null))
            {
                var r = await Git.RunAsync(p.Path, ct, "remote", "set-url", f.RemoteName!, f.Replacement!);
                if (r.Ok) undo.Remotes.Add((p.Path, f.RemoteName!, f.Value));
                else outcome.Errors.Add($"remote {f.RemoteName}: {r.StdErr.Trim()}");
            }
        }
        outcome.ItemsFixed = fixable.Count(f => !FixPlanner.TouchesHistory(f) || outcome.HistoryRewritten);
        return outcome;
    }

    private static string Full(ProjectInfo p, string rel) => Path.Combine(p.Path, rel.Replace('/', '\\'));

    internal static async Task AddToGitignoreAsync(ProjectInfo p, IEnumerable<string> rels, UndoBatch? undo, CancellationToken ct)
    {
        var gi = Path.Combine(p.Path, ".gitignore");
        var original = File.Exists(gi) ? await File.ReadAllBytesAsync(gi, ct) : null;
        var (text, kind) = original is null ? ("", TextEncodingKind.Utf8) : TextCodec.Decode(original);
        text ??= "";
        var existing = new HashSet<string>(text.Split('\n').Select(l => l.Trim()), StringComparer.Ordinal);
        var nl = text.Contains("\r\n", StringComparison.Ordinal) ? "\r\n" : "\n";
        var add = rels.Select(r => "/" + System.Text.RegularExpressions.Regex.Replace(r, @"([\[\]*?!#])", @"\$1")).Where(e => !existing.Contains(e)).Distinct().ToList();
        if (add.Count == 0) return;
        var sb = new StringBuilder(text);
        if (text.Length > 0 && !text.EndsWith('\n')) sb.Append(nl);
        sb.Append("# Added by Sanitization: sensitive or machine-specific files (kept on disk, never committed)").Append(nl);
        foreach (var e in add) sb.Append(e).Append(nl);
        var updated = TextCodec.Encode(sb.ToString(), kind);
        await AtomicWriteAsync(gi, updated, ct);
        undo?.Files.Add((gi, original, SHA256.HashData(updated)));
    }

    internal static async Task AtomicWriteAsync(string path, byte[] data, CancellationToken ct)
    {
        var tmp = path + ".sanitization-tmp";
        await File.WriteAllBytesAsync(tmp, data, ct);
        File.Move(tmp, path, true);
    }

    /// <summary>Restores the files of a batch. Files changed again since the fix are left alone and reported.</summary>
    public static async Task<List<string>> UndoAsync(UndoBatch batch, CancellationToken ct = default)
    {
        var problems = new List<string>();
        foreach (var (path, original, written) in Enumerable.Reverse(batch.Files))
        {
            try
            {
                if (File.Exists(path) && !SHA256.HashData(await File.ReadAllBytesAsync(path, ct)).AsSpan().SequenceEqual(written))
                {
                    problems.Add($"{path} was changed after the fix, so it was not restored.");
                    continue;
                }
                if (original is null) File.Delete(path);
                else await AtomicWriteAsync(path, original, ct);
            }
            catch (Exception e) { problems.Add($"{path}: {e.Message}"); }
        }
        foreach (var (repo, rel) in batch.Untracked)
        {
            var r = await Git.RunAsync(repo, ct, "add", "-f", "--", rel);
            if (!r.Ok) problems.Add($"{rel}: {r.StdErr.Trim()}");
        }
        foreach (var (repo, remote, url) in batch.Remotes)
        {
            var r = await Git.RunAsync(repo, ct, "remote", "set-url", remote, url);
            if (!r.Ok) problems.Add($"remote {remote}: {r.StdErr.Trim()}");
        }
        return problems;
    }
}
