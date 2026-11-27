using System.Net.Http;
using System.Text;
using Sanitization.Core;
using Xunit;

namespace Sanitization.Tests;

public class RuleTests
{
    private static RuleSet Rules(params PrivateTerm[] terms) => new(Fakes.Id, terms, []);

    [Fact]
    public void Real_looking_token_is_critical_and_placeholder_is_ignored()
    {
        var hits = Rules().ScanText($"a = \"{Fakes.GitHubToken}\"\nb = \"gh" + "p_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\"", "src/app.cs");
        var token = Assert.Single(hits, h => h.Rule.Category == "GitHub token");
        Assert.Equal(Severity.Critical, token.Severity);
        Assert.Equal(Fakes.GitHubToken, token.Value);
        Assert.Equal("REDACTED_SECRET", token.Replacement);
    }

    [Fact]
    public void Own_user_path_is_high_with_safe_replacement()
    {
        var hit = Assert.Single(Rules().ScanText($"log = @\"{Fakes.UserPath}\";", "a.cs"), h => h.Severity == Severity.High);
        Assert.Equal("Users\\" + Fakes.Id.UserName, hit.Value);
        Assert.Equal("Users\\user", hit.Replacement);
    }

    [Fact]
    public void Generic_findings_in_test_files_drop_to_low_but_own_identity_does_not()
    {
        var text = $"mail {Fakes.PersonalEmail} host {Fakes.Id.MachineName}";
        var hits = Rules().ScanText(text, "tests/Foo.Tests/MailTests.cs");
        Assert.Equal(Severity.Low, hits.Single(h => h.Rule.Category == "E-mail address").Severity);
        Assert.Equal(Severity.High, hits.Single(h => h.Rule.Category == "Your computer name").Severity);
    }

    [Fact]
    public void Private_terms_win_over_generic_rules()
    {
        var hits = Rules(new PrivateTerm { Value = Fakes.PersonalEmail, Replacement = "me@example.com" }).ScanText("contact " + Fakes.PersonalEmail, "README.md");
        var h = Assert.Single(hits);
        Assert.Equal("Your private info", h.Rule.Category);
        Assert.Equal("me@example.com", h.Replacement);
    }

    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("192.168.77.20")]
    [InlineData("203.0.113.5")]
    public void Harmless_ips_are_not_reported(string ip) =>
        Assert.DoesNotContain(Rules().ScanText($"server = {ip}", "a.txt"), h => h.Rule.Category == "Public IP address");

    [Fact]
    public void Version_numbers_are_not_ips_even_without_a_version_word() =>
        Assert.DoesNotContain(Rules().ScanText("Planned: 1.1.4.0 -> 1.1.5.0, fallback \"1.1.0.0\"", "notes.md"), h => h.Rule.Category == "Public IP address");

    [Fact]
    public void Version_numbers_are_not_ips() =>
        Assert.DoesNotContain(Rules().ScanText("Version 4.12.3.1 released", "notes.md"), h => h.Rule.Category == "Public IP address");

    [Fact]
    public void Ip_after_a_word_ending_in_ver_is_still_found() =>
        Assert.Contains(Rules().ScanText("Server: 198." + "20.47.61", "notes.md"), h => h.Rule.Category == "Public IP address");

    [Theory]
    [InlineData("chrome.storage.local.get(k)")]
    [InlineData("Left/Right/Up/Down/Home/End keys")]
    public void Code_is_not_mistaken_for_hosts_or_paths(string text) => Assert.Empty(Rules().ScanText(text, "src/app.js"));

    [Fact]
    public void Many_low_values_in_one_file_fold_into_one_row()
    {
        var p = new ProjectInfo { Name = "p", Path = "p" };
        var many = Enumerable.Range(1, 40).Select(i => new Finding { ProjectPath = "p", Kind = FindingKind.TextValue, Severity = Severity.Low,
            Category = "Public IP address", Why = "w", Value = $"45.1.2.{i}", RelativePath = "tests/feed.txt" }).ToList();
        var folded = Assert.Single(Scanner.Condense(p, many));
        Assert.Equal("Public IP address × 40", folded.Category);
        Assert.False(folded.Inspectable);
    }

    [Fact]
    public void Ignored_values_are_skipped()
    {
        var r = new RuleSet(Fakes.Id, [], [], [Fakes.PersonalEmail]);
        Assert.Empty(r.ScanText(Fakes.PersonalEmail, "a.txt"));
    }

    [Fact]
    public void Binary_with_build_path_is_detected()
    {
        var data = new byte[] { 0x4D, 0x5A, 0, 0 }.Concat(Encoding.ASCII.GetBytes(Fakes.UserPath + "\\obj\\a.pdb")).Concat(new byte[] { 0 }).ToArray();
        Assert.NotEmpty(Rules().ScanBinary(data));
    }
}

public class CodecTests
{
    [Fact]
    public void Utf16_bom_and_crlf_are_preserved()
    {
        var original = Encoding.Unicode.GetPreamble().Concat(Encoding.Unicode.GetBytes("a SECRETVALUE1 b\r\nline2\r\n")).ToArray();
        var updated = new Replacer(new Dictionary<string, string> { ["SECRETVALUE1"] = "X" }).Data(original);
        Assert.Equal(Encoding.Unicode.GetPreamble().Concat(Encoding.Unicode.GetBytes("a X b\r\nline2\r\n")).ToArray(), updated);
    }

    [Fact]
    public void Non_utf8_bytes_survive_round_trip()
    {
        var original = new byte[] { (byte)'k', (byte)'=', 0xE9, (byte)' ', (byte)'S', (byte)'1', (byte)'2', (byte)'3' };
        var updated = new Replacer(new Dictionary<string, string> { ["S123"] = "Z" }).Data(original);
        Assert.Equal(new byte[] { (byte)'k', (byte)'=', 0xE9, (byte)' ', (byte)'Z' }, updated);
    }

    [Fact]
    public void Replacement_respects_word_boundaries()
    {
        var r = new Replacer(new Dictionary<string, string> { ["bob"] = "X" });
        Assert.Equal("X bobby X", r.Text("bob bobby bob"));
    }

    [Fact]
    public void Quoted_fast_export_paths_are_decoded()
    {
        Assert.Equal("dir/a\"b.txt", HistoryRewriter.Unquote("\"dir/a\\\"b.txt\""));
        Assert.Equal("é.txt", HistoryRewriter.Unquote("\"\\303\\251.txt\""));
        Assert.Equal("keys/x.pfx", HistoryRewriter.ParseChangePath(Encoding.UTF8.GetBytes("M 100644 :12 keys/x.pfx")));
    }
}

public class ScanAndFixTests
{
    private static async Task<ProjectScanResult> Scan(TestRepo repo, IReadOnlyList<PrivateTerm>? terms = null) =>
        await Scanner.ScanAsync(repo.Info, Fakes.Id, terms ?? [], [], null, CancellationToken.None);

    [Fact]
    public async Task Finds_values_in_files_history_ignored_files_and_on_the_remote()
    {
        using var remote = new TestRepo(false);
        remote.Git("init", "-q", "--bare", "-b", "main");
        using var repo = new TestRepo();
        repo.Write("config.json", $"{{ \"token\": \"{Fakes.GitHubToken}\" }}");
        repo.Commit("add config");
        repo.Git("remote", "add", "origin", remote.Path);
        repo.Git("push", "-q", "origin", "main");
        repo.Write("config.json", "{ }");
        repo.Write(".gitignore", "local.txt\n");
        repo.Write("local.txt", "path " + Fakes.UserPath);
        repo.Commit("clean config");

        var result = await Scan(repo);
        var token = Assert.Single(result.Findings, f => f.Value == Fakes.GitHubToken);
        Assert.False(token.InWorkingTree);
        Assert.True(token.InLocalHistory);
        Assert.True(token.OnRemote);
        Assert.True(token.Actions.HasFlag(FixActions.RewriteHistory));
        var local = Assert.Single(result.Findings, f => f.RelativePath == "local.txt");
        Assert.Equal(FileState.Ignored, local.FileState);
        Assert.Equal(Severity.Critical, result.Findings[0].Severity);
    }

    [Fact]
    public async Task Fix_rewrites_history_drops_key_files_keeps_them_on_disk_and_rewrites_identities()
    {
        using var repo = new TestRepo();
        repo.Git("config", "user.email", Fakes.PersonalEmail);
        repo.Write("app.cs", $"var t = \"{Fakes.GitHubToken}\"; // {Fakes.UserPath}");
        repo.WriteBytes("sign.pfx", [1, 2, 3, 4]);
        repo.Commit("first by " + Fakes.Id.MachineName);
        repo.Write("readme.md", "hello");
        repo.Commit("second");

        var result = await Scan(repo);
        Assert.Contains(result.Findings, f => f.Kind == FindingKind.CommitIdentity && f.Value == Fakes.PersonalEmail);
        var undo = new UndoBatch();
        var outcome = await Fixer.ApplyAsync(result.Project, result.Findings.Where(f => f.CanFix).ToList(), true, undo, null, CancellationToken.None);

        Assert.Empty(outcome.Errors);
        Assert.True(outcome.HistoryRewritten);
        var everything = repo.Git("log", "--all", "-p", "--format=%an %ae %s %b");
        Assert.DoesNotContain(Fakes.GitHubToken, everything);
        Assert.DoesNotContain(Fakes.Id.UserName, everything);
        Assert.DoesNotContain(Fakes.Id.MachineName, everything);
        Assert.DoesNotContain(Fakes.PersonalEmail, everything);
        Assert.DoesNotContain("sign.pfx", repo.Git("log", "--all", "--name-only", "--format="));
        Assert.True(File.Exists(Path.Combine(repo.Path, "sign.pfx")));
        Assert.Contains("/sign.pfx", repo.Read(".gitignore"));
        Assert.Contains("REDACTED_SECRET", repo.Read("app.cs"));

        var after = await Scan(repo);
        Assert.DoesNotContain(after.Findings, f => f.Severity <= Severity.High && f.CanFix);
    }

    [Fact]
    public async Task Dirty_repo_fixes_files_but_blocks_history_and_undo_restores_files()
    {
        using var repo = new TestRepo();
        repo.Write("a.txt", "x " + Fakes.UserPath);
        repo.Commit("one");
        repo.Write("a.txt", "x " + Fakes.UserPath + " changed");

        var result = await Scan(repo);
        var undo = new UndoBatch();
        var outcome = await Fixer.ApplyAsync(result.Project, result.Findings.Where(f => f.CanFix).ToList(), true, undo, null, CancellationToken.None);
        Assert.NotNull(outcome.HistoryBlocked);
        Assert.False(outcome.HistoryRewritten);
        Assert.Contains(@"C:\Users\user\source", repo.Read("a.txt"));

        Assert.Empty(await Fixer.UndoAsync(undo));
        Assert.Contains(Fakes.Id.UserName, repo.Read("a.txt"));
    }

    [Fact]
    public async Task Non_git_folder_is_scanned_and_fixed_in_place()
    {
        using var dir = new TestRepo(false);
        dir.Write("notes/todo.txt", "deploy key " + Fakes.GitHubToken);
        var info = new ProjectInfo { Name = "plain", Path = dir.Path };
        var result = await Scanner.ScanAsync(info, Fakes.Id, [], [], null, CancellationToken.None);
        var f = Assert.Single(result.Findings);
        Assert.Equal(FileState.NotGit, f.FileState);
        var outcome = await Fixer.ApplyAsync(info, [f], true, new UndoBatch(), null, CancellationToken.None);
        Assert.Equal(1, outcome.FilesChanged);
        Assert.DoesNotContain(Fakes.GitHubToken, dir.Read("notes/todo.txt"));
    }

    [Fact]
    public void Discovery_lists_subfolders_and_nested_repos()
    {
        using var root = new TestRepo(false);
        Directory.CreateDirectory(Path.Combine(root.Path, "A", "bin"));
        Directory.CreateDirectory(Path.Combine(root.Path, "B", "inner", ".git"));
        Directory.CreateDirectory(Path.Combine(root.Path, "node_modules"));
        var names = ProjectDiscovery.Discover(root.Path).Select(p => p.Name).ToList();
        Assert.Equal(["A", "B", "B / inner"], names);
    }
}

public class SettingsAndReportTests
{
    [Fact]
    public void Settings_round_trip_encrypted()
    {
        var old = SettingsStore.Directory_;
        SettingsStore.Directory_ = Path.Combine(Path.GetTempPath(), "sanitization-tests", Guid.NewGuid().ToString("N"));
        try
        {
            var s = new AppSettings { ScanRoot = @"D:\dev" };
            s.PrivateTerms.Add(new PrivateTerm { Value = Fakes.PersonalEmail, Replacement = "me@example.com" });
            s.Ignore(@"D:\dev\App", "user26@example.com");
            SettingsStore.Save(s);
            Assert.DoesNotContain(Fakes.PersonalEmail, Encoding.UTF8.GetString(File.ReadAllBytes(SettingsStore.FilePath)));
            var back = SettingsStore.Load();
            Assert.Equal(@"D:\dev", back.ScanRoot);
            Assert.Equal(Fakes.PersonalEmail, back.PrivateTerms.Single().Value);
            Assert.Equal(["user26@example.com"], back.IgnoredFor(@"d:\DEV\app"));
        }
        finally
        {
            try { Directory.Delete(SettingsStore.Directory_, true); } catch { }
            SettingsStore.Directory_ = old;
        }
    }

    [Fact]
    public async Task Report_is_served_once_from_memory()
    {
        var finding = new Finding { ProjectPath = "p", Kind = FindingKind.TextValue, Severity = Severity.Critical, Category = "GitHub token", Why = "w", Value = "VALUE<1>" };
        var html = Report.BuildHtml(@"C:\dev", [new ProjectScanResult { Project = new ProjectInfo { Name = "P", Path = "p" }, Findings = [finding] }], DateTime.Now);
        Assert.Contains("VALUE&lt;1&gt;", html);
        var url = Report.ServeOnce(html);
        using var http = new HttpClient();
        var resp = await http.GetAsync(url);
        Assert.True(resp.Headers.CacheControl!.NoStore);
        Assert.Contains("VALUE&lt;1&gt;", await resp.Content.ReadAsStringAsync());
        await Assert.ThrowsAnyAsync<Exception>(async () => await http.GetStringAsync(url));
    }
}
