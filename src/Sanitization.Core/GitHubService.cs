using System.Text.Json;

namespace Sanitization.Core;

public sealed class ToolStatus
{
    public bool GitInstalled { get; init; }
    public string GitVersion { get; init; } = "";
    public bool GhInstalled { get; init; }
    public bool GhLoggedIn { get; init; }
    public string GhAccount { get; init; } = "";
    public bool GitHubReady => GhInstalled && GhLoggedIn;

    public string GitMissingMessage =>
        "Sanitization needs Git to read your repositories and their history.\n\n" +
        "To fix it:\n  1. Install Git for Windows from https://git-scm.com/download/win (keep the default options).\n" +
        "  2. Close and reopen Sanitization.";

    public string GitHubMissingMessage => !GhInstalled
        ? "Pushing and the \"delete & recreate repo\" guide need the GitHub CLI (gh), and it isn't installed.\n\n" +
          "To fix it:\n  1. Install it from https://cli.github.com (or run: winget install GitHub.cli).\n" +
          "  2. Open a terminal and run: gh auth login\n  3. Close and reopen Sanitization."
        : "The GitHub CLI (gh) is installed but not signed in.\n\nTo fix it:\n  1. Open a terminal and run: gh auth login\n  2. Close and reopen Sanitization.";

    public static async Task<ToolStatus> ProbeAsync(CancellationToken ct = default)
    {
        var git = await Proc.RunAsync("git", null, ["--version"], ct);
        var gh = await Proc.RunAsync("gh", null, ["--version"], ct);
        var loggedIn = false;
        var account = "";
        if (gh.Ok)
        {
            var who = await Proc.RunAsync("gh", null, ["api", "user", "--jq", ".login"], ct);
            loggedIn = who.Ok && who.StdOut.Trim().Length > 0;
            account = who.StdOut.Trim();
        }
        return new ToolStatus
        {
            GitInstalled = git.Ok, GitVersion = git.StdOut.Trim(), GhInstalled = gh.Ok, GhLoggedIn = loggedIn, GhAccount = account,
        };
    }
}

public sealed record RemoteRepoInfo(bool Exists, string Visibility, DateTimeOffset? CreatedAt, bool IsEmpty, string Error);

public static class GitHubService
{
    public static async Task<RemoteRepoInfo> GetRepoAsync(GitHubRepoRef repo, CancellationToken ct = default)
    {
        var r = await Proc.RunAsync("gh", null, ["repo", "view", repo.FullName, "--json", "visibility,createdAt,isEmpty"], ct);
        if (!r.Ok) return new RemoteRepoInfo(false, "", null, false, r.StdErr.Trim());
        try
        {
            using var doc = JsonDocument.Parse(r.StdOut);
            var root = doc.RootElement;
            var vis = root.TryGetProperty("visibility", out var v) ? v.GetString() ?? "" : "";
            DateTimeOffset? created = root.TryGetProperty("createdAt", out var c) && DateTimeOffset.TryParse(c.GetString(), out var d) ? d : null;
            var empty = root.TryGetProperty("isEmpty", out var e) && e.ValueKind == JsonValueKind.True;
            return new RemoteRepoInfo(true, vis, created, empty, "");
        }
        catch (Exception ex)
        {
            return new RemoteRepoInfo(false, "", null, false, ex.Message);
        }
    }

    public static string SettingsUrl(GitHubRepoRef r) => $"{r.Url}/settings";
    public static string ReleasesUrl(GitHubRepoRef r) => $"{r.Url}/releases";
    public static string NewRepoUrl(GitHubRepoRef r, string visibility) =>
        $"https://github.com/new?name={Uri.EscapeDataString(r.Name)}&owner={Uri.EscapeDataString(r.Owner)}&visibility={(visibility.Equals("public", StringComparison.OrdinalIgnoreCase) ? "public" : "private")}";

    public static async Task<(bool Ok, string Log)> ForcePushAsync(string repo, bool lease, CancellationToken ct = default)
    {
        var log = new System.Text.StringBuilder();
        var branches = await Git.RunAsync(repo, ct, "push", lease ? "--force-with-lease" : "--force", "--all", "origin");
        log.AppendLine(branches.StdErr.Trim());
        if (!branches.Ok) return (false, log.ToString());
        var tags = await Git.RunAsync(repo, ct, "push", "--force", "--tags", "origin");
        log.AppendLine(tags.StdErr.Trim());
        if (!tags.Ok) return (false, log.ToString());
        await Git.RunAsync(repo, ct, "fetch", "--prune", "--prune-tags", "origin");
        return (true, log.ToString());
    }

    public static async Task<List<string>> StaleRemoteBranchesAsync(string repo, CancellationToken ct = default)
    {
        var list = new List<string>();
        foreach (var line in (await Git.TryOutAsync(repo, ct, "for-each-ref", "--format=%(refname:short)%00%(symref)", "refs/remotes")).Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = line.Split('\0');
            if (parts.Length < 2 || parts[1].Length > 0) continue;
            var n = (await Git.TryOutAsync(repo, ct, "rev-list", "--count", parts[0], "--not", "--branches", "--tags")).Trim();
            if (int.TryParse(n, out var c) && c > 0) list.Add(parts[0]);
        }
        return list;
    }
}
