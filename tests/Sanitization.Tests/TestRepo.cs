using System.Diagnostics;
using Sanitization.Core;

namespace Sanitization.Tests;

/// <summary>Temporary git repository. Every sensitive-looking value is built at runtime, so this source file holds none.</summary>
internal sealed class TestRepo : IDisposable
{
    public string Path { get; }

    public TestRepo(bool init = true)
    {
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "sanitization-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path);
        if (!init) return;
        Git("init", "-q", "-b", "main");
        Git("config", "user.email", "t@users.noreply.github.com");
        Git("config", "user.name", "Tester");
        Git("config", "core.autocrlf", "false");
        Git("config", "commit.gpgsign", "false");
    }

    public string Git(params string[] args)
    {
        var psi = new ProcessStartInfo("git") { WorkingDirectory = Path, RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        foreach (var a in args) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)!;
        var o = p.StandardOutput.ReadToEnd();
        var e = p.StandardError.ReadToEnd();
        p.WaitForExit();
        if (p.ExitCode != 0) throw new InvalidOperationException($"git {string.Join(' ', args)}: {e}");
        return o;
    }

    public void Write(string rel, string content) => WriteBytes(rel, System.Text.Encoding.UTF8.GetBytes(content));

    public void WriteBytes(string rel, byte[] content)
    {
        var full = System.IO.Path.Combine(Path, rel);
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(full)!);
        File.WriteAllBytes(full, content);
    }

    public string Read(string rel) => File.ReadAllText(System.IO.Path.Combine(Path, rel));

    public void Commit(string message)
    {
        Git("add", "-A");
        Git("commit", "-q", "-m", message);
    }

    public ProjectInfo Info => new() { Name = "repo", Path = Path, IsGit = Core.Git.IsRepo(Path) };

    public void Dispose()
    {
        try
        {
            foreach (var f in Directory.EnumerateFiles(Path, "*", SearchOption.AllDirectories)) File.SetAttributes(f, FileAttributes.Normal);
            Directory.Delete(Path, true);
        }
        catch { }
    }
}

internal static class Fakes
{
    public static readonly MachineIdentity Id = new()
    {
        UserName = "zqtestuser", MachineName = "ZQ-WORKSTATION", Sid = "S-1-5-21-" + "3141592653-2718281828-1618033988-1001",
        GlobalGitEmail = "t@users.noreply.github.com",
    };

    // Built from parts so no real-looking token sits in source code (the scanner scans this repo too).
    public static string GitHubToken => "gh" + "p_" + "Qw7Rt9Yp2Lk4Hj6Gf8Ds1Az3Xc5Vb0NmPoIuY";
    public static string PersonalEmail => "zq.fixture" + "@" + "mailbox.org";
    public static string UserPath => "C:\\Users\\" + Id.UserName + "\\source\\app";
}
