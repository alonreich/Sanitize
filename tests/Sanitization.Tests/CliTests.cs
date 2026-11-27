using Sanitization.Core;
using Xunit;

namespace Sanitization.Tests;

public class CliTests
{
    private static async Task<(int Code, string Out)> Run(params string[] args)
    {
        var o = new StringWriter();
        var e = new StringWriter();
        var old = SettingsStore.Directory_;
        SettingsStore.Directory_ = Path.Combine(Path.GetTempPath(), "sanitization-tests", "cli-" + Guid.NewGuid().ToString("N"));
        try
        {
            var code = await CliApp.RunAsync(args, o, e);
            return (code, o + e.ToString());
        }
        finally { SettingsStore.Directory_ = old; }
    }

    [Fact]
    public async Task Scan_prints_one_line_per_finding_with_id_and_exit_1()
    {
        using var root = new TestRepo(false);
        Directory.CreateDirectory(Path.Combine(root.Path, "App"));
        File.WriteAllText(Path.Combine(root.Path, "App", "deploy.txt"), "token " + Fakes.GitHubToken);
        var (code, text) = await Run("scan", root.Path);
        Assert.Equal(1, code);
        var line = Assert.Single(text.Split('\n'), l => l.StartsWith("  F ", StringComparison.Ordinal));
        Assert.Contains("| CRITICAL | GitHub token | value=" + Fakes.GitHubToken, line);
        Assert.Contains("at=deploy.txt:1", line);
        Assert.Contains("PROJECT App |", text);
        Assert.Contains("END | exit=1", text);
    }

    [Fact]
    public async Task Fix_by_id_removes_it_and_exits_0()
    {
        using var root = new TestRepo(false);
        Directory.CreateDirectory(Path.Combine(root.Path, "App"));
        File.WriteAllText(Path.Combine(root.Path, "App", "deploy.txt"), "token " + Fakes.GitHubToken);
        var (_, scan) = await Run("scan", root.Path, "--json");
        var id = System.Text.Json.JsonDocument.Parse(scan).RootElement.GetProperty("projects")[0].GetProperty("findings")[0].GetProperty("id").GetString()!;
        var (code, text) = await Run("fix", root.Path, "--id", id, "--replace", id + "=XXX");
        Assert.Equal(0, code);
        Assert.Contains("remaining=0", text);
        Assert.Equal("token XXX", File.ReadAllText(Path.Combine(root.Path, "App", "deploy.txt")));
    }

    [Fact]
    public async Task Bad_usage_exits_2_with_help()
    {
        var (code, text) = await Run("fix");
        Assert.Equal(2, code);
        Assert.Contains("ai-sanitize scan", text);
    }

    [Fact]
    public void Escaping_keeps_one_record_per_line() =>
        Assert.Equal(@"a\nb \| C:\x", CliApp.Esc("a\nb | C:\\x"));
}
