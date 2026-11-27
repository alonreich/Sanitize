using System.Diagnostics;
using System.Text;

namespace Sanitization.Core;

public sealed record ProcessResult(int ExitCode, string StdOut, string StdErr)
{
    public bool Ok => ExitCode == 0;
}

public static class Proc
{
    public static ProcessStartInfo StartInfo(string exe, string? workDir, IEnumerable<string> args)
    {
        var psi = new ProcessStartInfo(exe)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        if (workDir is not null) psi.WorkingDirectory = workDir;
        foreach (var a in args) psi.ArgumentList.Add(a);
        psi.Environment["GIT_TERMINAL_PROMPT"] = "0";
        psi.Environment["GH_PROMPT_DISABLED"] = "1";
        psi.Environment["GH_NO_UPDATE_NOTIFIER"] = "1";
        psi.Environment["LC_ALL"] = "C";
        return psi;
    }

    public static async Task<ProcessResult> RunAsync(string exe, string? workDir, IEnumerable<string> args, CancellationToken ct = default, byte[]? stdin = null)
    {
        using var p = new Process { StartInfo = StartInfo(exe, workDir, args) };
        try
        {
            p.Start();
        }
        catch (Exception e)
        {
            return new ProcessResult(-1, "", e.Message);
        }
        var outTask = p.StandardOutput.ReadToEndAsync(ct);
        var errTask = p.StandardError.ReadToEndAsync(ct);
        if (stdin is not null) await p.StandardInput.BaseStream.WriteAsync(stdin, ct);
        p.StandardInput.Close();
        try
        {
            await p.WaitForExitAsync(ct);
        }
        catch (OperationCanceledException)
        {
            try { p.Kill(true); } catch { }
            throw;
        }
        return new ProcessResult(p.ExitCode, await outTask, await errTask);
    }
}

public static class Git
{
    public static Task<ProcessResult> RunAsync(string repo, CancellationToken ct, params string[] args) =>
        Proc.RunAsync("git", repo, ["-c", "core.quotepath=false", "-c", "color.ui=never", .. args], ct);

    public static Task<ProcessResult> RunWithInputAsync(string repo, byte[] stdin, CancellationToken ct, params string[] args) =>
        Proc.RunAsync("git", repo, ["-c", "core.quotepath=false", .. args], ct, stdin);

    public static async Task<string> OutAsync(string repo, CancellationToken ct, params string[] args)
    {
        var r = await RunAsync(repo, ct, args);
        if (!r.Ok) throw new InvalidOperationException($"git {string.Join(' ', args)} failed: {r.StdErr.Trim()}");
        return r.StdOut;
    }

    public static async Task<string> TryOutAsync(string repo, CancellationToken ct, params string[] args)
    {
        var r = await RunAsync(repo, ct, args);
        return r.Ok ? r.StdOut : "";
    }

    public static bool IsRepo(string path) => Directory.Exists(Path.Combine(path, ".git")) || File.Exists(Path.Combine(path, ".git"));

    public static IEnumerable<string> SplitZ(string s) => s.Split('\0', StringSplitOptions.RemoveEmptyEntries);

    public static async IAsyncEnumerable<(string Sha, byte[] Data)> CatBlobsAsync(string repo, IReadOnlyList<string> shas,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        if (shas.Count == 0) yield break;
        var psi = Proc.StartInfo("git", repo, ["cat-file", "--batch"]);
        psi.StandardOutputEncoding = null;
        using var p = new Process { StartInfo = psi };
        p.Start();
        _ = p.StandardError.ReadToEndAsync(ct);
        var writer = Task.Run(async () =>
        {
            try
            {
                var input = p.StandardInput.BaseStream;
                foreach (var sha in shas)
                {
                    ct.ThrowIfCancellationRequested();
                    await input.WriteAsync(Encoding.ASCII.GetBytes(sha + "\n"), ct);
                }
                await input.FlushAsync(ct);
            }
            catch { }
            finally
            {
                try { p.StandardInput.Close(); } catch { }
            }
        }, ct);
        var reader = new ByteReader(p.StandardOutput.BaseStream);
        try
        {
            while (true)
            {
                ct.ThrowIfCancellationRequested();
                var header = await reader.ReadLineAsync(ct);
                if (header is null) break;
                var parts = Encoding.ASCII.GetString(header).Split(' ');
                if (parts.Length < 3 || parts[1] == "missing") continue;
                var size = long.Parse(parts[2]);
                var data = await reader.ReadExactAsync((int)size, ct);
                await reader.ReadExactAsync(1, ct);
                yield return (parts[0], data);
            }
        }
        finally
        {
            try { if (!p.HasExited) p.Kill(true); } catch { }
            try { await writer; } catch { }
        }
    }
}

public sealed class ByteReader(Stream stream)
{
    private readonly byte[] _buf = new byte[1 << 16];
    private int _pos, _len;

    private async ValueTask<bool> FillAsync(CancellationToken ct)
    {
        _len = await stream.ReadAsync(_buf, ct);
        _pos = 0;
        return _len > 0;
    }

    public async ValueTask<byte[]?> ReadLineAsync(CancellationToken ct)
    {
        var ms = new MemoryStream();
        while (true)
        {
            if (_pos >= _len && !await FillAsync(ct)) return ms.Length > 0 ? ms.ToArray() : null;
            var idx = Array.IndexOf(_buf, (byte)'\n', _pos, _len - _pos);
            if (idx >= 0)
            {
                ms.Write(_buf, _pos, idx - _pos);
                _pos = idx + 1;
                return ms.ToArray();
            }
            ms.Write(_buf, _pos, _len - _pos);
            _pos = _len;
        }
    }

    public async ValueTask<byte[]> ReadExactAsync(int count, CancellationToken ct)
    {
        var result = new byte[count];
        var off = 0;
        while (off < count)
        {
            if (_pos >= _len && !await FillAsync(ct)) throw new EndOfStreamException("Unexpected end of git output.");
            var n = Math.Min(count - off, _len - _pos);
            Buffer.BlockCopy(_buf, _pos, result, off, n);
            _pos += n;
            off += n;
        }
        return result;
    }
}
