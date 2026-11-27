using System.IO.Compression;
using System.Text;
using Sanitization.Core;
using Xunit;

namespace Sanitization.Tests;

/// <summary>Covers the deeper-detection work: full identity, noreply handles, all refs, UTF-16 logs, screenshots, committed logs,
/// build output, infrastructure dumps, employer, bundles / .git leftovers, safe placeholders, code-not-hosts, packed DLLs, distinct placeholders.
/// Fictional values only; anything the scanner must detect is assembled at run time so this file stays clean.</summary>
public class DeeperDetectionTests
{
    private const string Name = "Zqa Testerman";
    private const string Handle = "zqhandle";
    private static readonly string Noreply = "98765+" + Handle + "@users.noreply" + ".github.com";
    private static readonly string Org = "Zqcorp Data Communications Ltd";

    private static MachineIdentity Owner()
    {
        var names = new List<string>();
        var handles = new List<string>();
        var emails = new List<string>();
        var orgs = new List<string>();
        IdentityText.AddName(Name, names, handles);
        IdentityText.AddEmail(Noreply, emails, handles);
        IdentityText.AddOrg(Org, orgs);
        return new MachineIdentity
        {
            UserName = Fakes.Id.UserName, MachineName = Fakes.Id.MachineName, Sid = Fakes.Id.Sid, GlobalGitEmail = Noreply,
            FullNames = names, Handles = handles, ExtraEmails = emails, Organisations = orgs,
        };
    }

    private static RuleSet Rules(MachineIdentity? id = null) => new(id ?? Owner(), [], []);

    private static Task<ProjectScanResult> Scan(TestRepo repo, MachineIdentity? id = null) =>
        Scanner.ScanAsync(repo.Info, id ?? Owner(), [], [], null, CancellationToken.None);

    // 1 + 10: name, name in author fields, name-based e-mail, employer
    [Fact]
    public void Full_name_first_name_in_author_fields_name_email_and_employer_are_found()
    {
        var personal = "zqa.testerman" + "@" + "mailbox.org";
        var text = $"Copyright (c) 2026 {Name}. All rights reserved.\n<Company>Zqa</Company>\nkey.SetValue(\"Publisher\", \"Zqa\");\nmail {personal}\ngroup Zqcorp Cloud";
        var hits = Rules().ScanText(text, "Directory.Build.props");
        Assert.Contains(hits, h => h.Rule.Category == "Your name" && h.Value == Name && h.Replacement == "Dev User");
        Assert.Equal(2, hits.Count(h => h.Rule.Category == "Your name (author / company field)" && h.Value == "Zqa"));
        Assert.Contains(hits, h => h.Rule.Category == "Your personal e-mail" && h.Value == personal && h.Replacement == "dev@example.com");
        Assert.Contains(hits, h => h.Rule.Category == "Your organisation's name" && h.Value == "Zqcorp" && h.Replacement == "Contoso");
        Assert.DoesNotContain(Rules().ScanText("Zqa went home", "notes.md"), h => h.Value == "Zqa");
    }

    [Fact]
    public void Identity_text_parses_noreply_handles_onedrive_orgs_and_ignores_placeholders()
    {
        var names = new List<string>();
        var handles = new List<string>();
        var emails = new List<string>();
        IdentityText.AddEmail(Noreply, emails, handles);
        IdentityText.AddName("Dev User", names, handles);
        IdentityText.AddEmail("dev@example.com", emails, handles);
        Assert.Equal([Handle], handles);
        Assert.Equal([Noreply], emails);
        Assert.Empty(names);
        Assert.Equal("Zqcorp Ltd", IdentityText.OrgFromOneDriveFolder(@"C:\Users\x\OneDrive - Zqcorp Ltd"));
        Assert.Equal("", IdentityText.OrgFromOneDriveFolder(@"C:\Users\x\OneDrive"));
    }

    // 2 + 3: noreply handle and the handle itself
    [Fact]
    public void Github_handle_is_found_in_content_and_the_noreply_address_is_not_trusted()
    {
        var hits = Rules().ScanText($"https://github.com/{Handle}/app/releases\nRepositoryOwner = \"{Handle}\";\nauthor {Noreply}", "UpdateService.cs");
        Assert.Equal(2, hits.Count(h => h.Rule.Category == "Your GitHub / git user name"));
        Assert.Contains(hits, h => h.Rule.Category == "Your GitHub e-mail (shows your user name)" && h.Replacement == "dev@example.com");
    }

    [Fact]
    public async Task Commit_identities_with_a_noreply_handle_are_reported_and_rewritten_and_repo_git_config_is_fixed()
    {
        using var repo = new TestRepo();
        repo.Git("config", "user.email", Noreply);
        repo.Git("config", "user.name", Handle);
        repo.Write("a.txt", "hello");
        repo.Commit("first");

        var result = await Scan(repo, Fakes.Id);
        var mail = Assert.Single(result.Findings, f => f.Category == "GitHub user name in commit e-mail");
        Assert.Equal("dev@example.com", mail.Replacement);
        var name = Assert.Single(result.Findings, f => f.Kind == FindingKind.CommitIdentity && f.Value == Handle);
        Assert.Equal("Dev User", name.Replacement);
        var config = result.Findings.Where(f => f.Kind == FindingKind.GitConfig).ToList();
        Assert.Equal(2, config.Count);

        var outcome = await Fixer.ApplyAsync(result.Project, result.Findings.Where(f => f.CanFix).ToList(), true, new UndoBatch(), null, CancellationToken.None);
        Assert.True(outcome.HistoryRewritten, string.Join("; ", outcome.Errors));
        Assert.Equal("Dev User|dev@example.com", repo.Git("log", "-1", "--format=%an|%ae").Trim());
        Assert.Equal("Dev User", repo.Git("config", "--local", "user.name").Trim());
        Assert.Equal("dev@example.com", repo.Git("config", "--local", "user.email").Trim());
    }

    // 4: refs that point straight at a tree (tool snapshots)
    [Fact]
    public async Task Snapshot_refs_pointing_at_trees_are_scanned_and_rewritten()
    {
        using var repo = new TestRepo();
        repo.Write("a.txt", "clean");
        repo.Commit("first");
        repo.Write("snap.txt", "token " + Fakes.GitHubToken);
        repo.Git("add", "snap.txt");
        var tree = repo.Git("write-tree").Trim();
        repo.Git("update-ref", "refs/codex/checkpoints/one", tree);
        repo.Git("rm", "-q", "--cached", "snap.txt");
        File.Delete(Path.Combine(repo.Path, "snap.txt"));

        var result = await Scan(repo, Fakes.Id);
        var token = Assert.Single(result.Findings, f => f.Value == Fakes.GitHubToken);
        Assert.True(token.InLocalHistory);

        var outcome = await Fixer.ApplyAsync(result.Project, [token], true, new UndoBatch(), null, CancellationToken.None);
        Assert.True(outcome.HistoryRewritten, string.Join("; ", outcome.Errors));
        var content = repo.Git("cat-file", "-p", "refs/codex/checkpoints/one:snap.txt");
        Assert.DoesNotContain(Fakes.GitHubToken, content);
        Assert.Contains("REDACTED_SECRET", content);
    }

    // 5: UTF-16 text without a BOM
    [Fact]
    public void Utf16_text_without_bom_is_decoded_scanned_and_round_trips()
    {
        var bytes = Encoding.Unicode.GetBytes("Build started.\r\nOutput: " + Fakes.UserPath + "\r\nDone building project.\r\n");
        var (text, kind) = TextCodec.Decode(bytes);
        Assert.Equal(TextEncodingKind.Utf16LeNoBom, kind);
        Assert.Contains(Fakes.UserPath, text);
        Assert.Equal(bytes, TextCodec.Encode(text!, kind));
        Assert.Contains(Rules().ScanText(text!, "build.log"), h => h.Rule.Category == "Your Windows user name (in a path)");
        Assert.Equal(TextEncodingKind.Binary, TextCodec.Decode([0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0xB8, 0x00]).Kind);
    }

    // 6: screenshots (the OCR itself is Windows; here: what is and isn't treated as a picture)
    [Fact]
    public async Task Picture_reader_ignores_non_images_and_tiny_images()
    {
        Assert.False(ImageText.LooksLikeImage(Encoding.ASCII.GetBytes("not an image at all")));
        Assert.True(ImageText.LooksLikeImage([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0]));
        Assert.Null(await ImageText.ReadAsync(Encoding.ASCII.GetBytes("plain text"), CancellationToken.None));
    }

    // 7: committed logs / test results
    [Fact]
    public async Task Committed_logs_and_test_results_are_flagged_and_dropped_from_history()
    {
        using var repo = new TestRepo();
        repo.Write("src/app.txt", "ok");
        repo.Write("tests/TestResults/run.trx", "<TestRun name=\"x\" />");
        repo.Commit("first");

        var result = await Scan(repo, Fakes.Id);
        var log = Assert.Single(result.Findings, f => f.Category == "Log / test-result file committed to git");
        Assert.True(log.Actions.HasFlag(FixActions.DropFromHistory));
        Assert.True(log.Actions.HasFlag(FixActions.Untrack));
        var outcome = await Fixer.ApplyAsync(result.Project, [log], true, new UndoBatch(), null, CancellationToken.None);
        Assert.True(outcome.HistoryRewritten, string.Join("; ", outcome.Errors));
        Assert.DoesNotContain("run.trx", repo.Git("log", "--all", "--name-only", "--format="));
    }

    // 8: build output
    [Fact]
    public async Task Build_output_with_your_user_path_is_one_row_and_the_fix_deletes_it()
    {
        using var repo = new TestRepo();
        repo.Write(".gitignore", "bin/\nobj/\n");
        repo.Write("src/App/App.csproj", "<Project />");
        repo.Commit("first");
        repo.Write("src/App/obj/project.assets.json", "{ \"packageFolders\": { \"" + Fakes.UserPath.Replace("\\", "\\\\") + "\": {} } }");
        repo.Write("src/App/bin/readme.txt", "nothing personal");

        var result = await Scan(repo, Fakes.Id);
        var build = Assert.Single(result.Findings, f => f.Category == "Build output contains your PC info");
        Assert.Equal(["src/App/obj"], build.Folders);
        Assert.Equal(FixActions.DeleteFolders, build.Actions);
        await Fixer.ApplyAsync(result.Project, [build], false, new UndoBatch(), null, CancellationToken.None);
        Assert.False(Directory.Exists(Path.Combine(repo.Path, "src", "App", "obj")));
        Assert.True(Directory.Exists(Path.Combine(repo.Path, "src", "App", "bin")));
    }

    // 9: captured infrastructure
    [Fact]
    public async Task Dumps_of_internal_addresses_and_servers_are_flagged()
    {
        using var repo = new TestRepo();
        var sb = new StringBuilder("asset export\n");
        for (var i = 0; i < 12; i++) sb.Append("10.6.100.").Append(20 + i).Append("\tsrv-").Append(i).Append(".zqcorp-fict").Append(".co.il\tvCenter\n");
        repo.Write("sessions/audit/assets.txt", sb.ToString());
        repo.Write(".gitignore", "sessions/\n");
        repo.Commit("first");

        var result = await Scan(repo, Fakes.Id);
        var dump = Assert.Single(result.Findings, f => f.Category == "Captured network / customer data");
        Assert.Equal(Severity.High, dump.Severity);
        Assert.Contains("internal IPs", dump.Snippet);
        Assert.Contains("zqcorp-fict.co.il", dump.Snippet);
    }

    [Fact]
    public async Task Dotted_names_in_code_are_not_a_server_dump()
    {
        using var repo = new TestRepo();
        var sb = new StringBuilder("using System;\n");
        foreach (var n in new[] { "Media", "Controls", "Input", "Layout", "Shapes", "Threading", "Markup", "Platform", "Storage", "Styling" })
            sb.Append("using Avalonia.").Append(n).Append(".Core;\nvar x = this.state.").Append(n.ToLowerInvariant()).Append(".value;\n");
        repo.Write("src/App/MainWindow.cs", sb.ToString());
        repo.Commit("first");
        var result = await Scan(repo, Fakes.Id);
        Assert.DoesNotContain(result.Findings, f => f.Category == "Captured network / customer data");
    }

    // 11: bundles, lost-found, stale worktree links
    [Fact]
    public async Task Bundles_lost_found_and_stale_worktree_links_are_found()
    {
        using var repo = new TestRepo();
        repo.Write("a.txt", "x");
        repo.Commit("first");
        repo.Write(".gitignore", "*.bundle\n");
        repo.Write("old-backup.bundle", "# v2 git bundle\n0000000000000000000000000000000000000000 refs/heads/main\n\n");
        repo.Write(".git/lost-found/other/0123", "path " + Fakes.UserPath);
        var missing = "C:/Users/" + Fakes.Id.UserName + "/AppData/Local/Temp/gone-wt/.git";
        repo.Write(".git/worktrees/gone-wt/gitdir", missing + "\n");

        var result = await Scan(repo, Fakes.Id);
        var bundle = Assert.Single(result.Findings, f => f.Category.StartsWith("Git backup bundle", StringComparison.Ordinal));
        Assert.False(bundle.CanFix);
        var lost = Assert.Single(result.Findings, f => f.Category == "Recovered old files (.git/lost-found)");
        Assert.Equal(Severity.Medium, lost.Severity);
        Assert.Equal(FixActions.DeleteFolders, lost.Actions);
        var wt = Assert.Single(result.Findings, f => f.Category == "Git worktree link with your user path");
        Assert.Equal(FixActions.SetGitConfig, wt.Actions);

        await Fixer.ApplyAsync(result.Project, [lost, wt], false, new UndoBatch(), null, CancellationToken.None);
        Assert.False(Directory.Exists(Path.Combine(repo.Path, ".git", "lost-found")));
        Assert.False(Directory.Exists(Path.Combine(repo.Path, ".git", "worktrees", "gone-wt")));
    }

    // 13: our own safe stand-ins are never reported
    [Theory]
    [InlineData("server nas.contoso.local and printer.contoso.local")]
    [InlineData("https://fabrikam-prod.service-now.com/now and https://contoso2.service-now.com")]
    [InlineData("mail dev@example.com or user27@example.com")]
    [InlineData(@"path C:\Users\user3\b.txt and C:\Users\user\x")]
    [InlineData("host pc1.contoso.local or host.example.internal")]
    public void Safe_placeholders_are_not_reported(string text) =>
        Assert.DoesNotContain(new RuleSet(new MachineIdentity { GlobalGitEmail = "dev@example.com" }, [], []).ScanText(text, "notes.md"), h => h.Severity <= Severity.Medium);

    [Fact]
    public void Map_files_are_skipped() =>
        Assert.True(Path.GetFileName("Sanitization/sanitize-map.local.json").Contains("sanitize-map", StringComparison.OrdinalIgnoreCase));

    // 14: code is not a host name
    [Fact]
    public void Property_access_in_code_is_not_a_host_name_but_a_quoted_host_is()
    {
        Assert.DoesNotContain(Rules().ScanText("if (imported.local && typeof imported.local === 'object') {}", "utils.js"), h => h.Rule.Category == "Internal host name");
        Assert.Contains(Rules(Fakes.Id).ScanText("const host = \"build01.zqnet.local\";", "deploy.js"), h => h.Rule.Category == "Internal host name");
        Assert.Contains(Rules(Fakes.Id).ScanText("server build01.zqnet.local", "notes.md"), h => h.Rule.Category == "Internal host name");
    }

    // 15: packed DLLs
    [Fact]
    public async Task Gzipped_programs_are_unpacked_and_only_reported_when_they_hold_your_identity()
    {
        using var repo = new TestRepo();
        static byte[] Gz(byte[] data)
        {
            using var ms = new MemoryStream();
            using (var gz = new GZipStream(ms, CompressionLevel.Fastest, true)) gz.Write(data);
            return ms.ToArray();
        }
        repo.WriteBytes("libs/clean.dll.gz", Gz([0x4D, 0x5A, 0x90, 0x00, 1, 2, 3, 4, 5, 6, 7, 8]));
        repo.WriteBytes("libs/mine.dll.gz", Gz([0x4D, 0x5A, 0x90, 0x00, .. Encoding.ASCII.GetBytes(" pdb " + Fakes.UserPath + " ")]));
        repo.Commit("first");

        var result = await Scan(repo, Fakes.Id);
        Assert.DoesNotContain(result.Findings, f => f.RelativePath == "libs/clean.dll.gz");
        Assert.Single(result.Findings, f => f.RelativePath == "libs/mine.dll.gz" && f.Category == "Compiled file contains your PC info");
    }

    // 16: distinct placeholders
    [Fact]
    public void Duplicate_placeholders_saved_by_older_versions_are_repaired()
    {
        var store = new Dictionary<string, string> { ["a"] = "ipv4:203.0.113.49", ["b"] = "ipv4:203.0.113.49", ["c"] = "email:user@example.com" };
        var map = new PlaceholderMap(store);
        Assert.Equal(store.Count, store.Values.Distinct().Count());
        Assert.StartsWith("ipv4:203.0.113.", store["b"]);
        Assert.NotEqual(map.For("ipv4", "198." + "20.47.1"), map.For("ipv4", "198." + "20.47.2"));
    }

    [Fact]
    public async Task Two_ips_in_two_files_get_two_different_placeholders()
    {
        using var repo = new TestRepo();
        var ip1 = "198." + "20.47.61";
        var ip2 = "198." + "20.47.62";
        repo.Write("docs/a.md", "server " + ip1);
        repo.Write("docs/b.md", "server " + ip2 + " and " + ip1);
        repo.Commit("first");
        var result = await Scan(repo, Fakes.Id);
        var r1 = result.Findings.Where(f => f.Value == ip1).Select(f => f.Replacement).Distinct().ToList();
        var r2 = result.Findings.Where(f => f.Value == ip2).Select(f => f.Replacement).Distinct().ToList();
        Assert.Single(r1);
        Assert.Single(r2);
        Assert.NotEqual(r1[0], r2[0]);
    }

    [Fact]
    public async Task Other_peoples_user_names_get_numbered_placeholders()
    {
        using var repo = new TestRepo();
        repo.Write("docs/a.md", @"see C:\Users\zqdana\x.txt and C:\Users\zqjonas\y.txt");
        repo.Commit("first");
        var result = await Scan(repo, Fakes.Id);
        var reps = result.Findings.Where(f => f.Category == "Someone's user name (in a path)").Select(f => f.Replacement).ToList();
        Assert.Equal(2, reps.Distinct().Count());
        Assert.All(reps, r => Assert.Matches(@"^C:\\Users\\user\d+$", r));
    }
}
