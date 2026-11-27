using System.Diagnostics;
using System.Text;

namespace Sanitization.Core;

/// <summary>
/// Rewrites git history natively: git fast-export | (filter in memory) | git fast-import.
/// Nothing sensitive is written to disk and no extra tool (git-filter-repo) is needed.
/// Remote-tracking refs (refs/remotes/*) and the stash are left alone, so the app can still tell what the
/// remote has until you push. Commits keep their dates and authors (except the e-mails you chose to replace).
/// </summary>
public static class HistoryRewriter
{
    public sealed record Plan(IReadOnlyDictionary<string, string> Replacements, IReadOnlySet<string> DropPaths, IReadOnlyDictionary<string, string> EmailMap)
    {
        public bool IsEmpty => Replacements.Count == 0 && DropPaths.Count == 0 && EmailMap.Count == 0;
    }

    public static async Task RewriteAsync(string repo, Plan plan, IProgress<string>? progress, CancellationToken ct)
    {
        if (plan.IsEmpty) return;
        var refs = new List<string>();
        foreach (var line in (await Git.OutAsync(repo, ct, "for-each-ref", "--format=%(refname)%00%(symref)")).Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = line.Split('\0');
            if (parts.Length < 2 || parts[1].Length > 0) continue;
            var r = parts[0];
            if (r.StartsWith("refs/remotes/", StringComparison.Ordinal) || r == "refs/stash") continue;
            refs.Add(r);
        }
        if (refs.Count == 0) throw new InvalidOperationException("No branches or tags to rewrite.");

        var supportsSignedCommits = (await Git.RunAsync(repo, ct, "fast-export", "-h")).StdErr.Contains("--signed-commits", StringComparison.Ordinal)
                                    || (await Git.RunAsync(repo, ct, "fast-export", "-h")).StdOut.Contains("--signed-commits", StringComparison.Ordinal);
        List<string> exportArgs = ["-c", "core.quotepath=false", "fast-export", "--signed-tags=strip", "--tag-of-filtered-object=rewrite", "--fake-missing-tagger",
            "--reference-excluded-parents", "--use-done-feature", "--reencode=yes"];
        if (supportsSignedCommits) exportArgs.Add("--signed-commits=strip");
        exportArgs.AddRange(refs);

        var exportPsi = Proc.StartInfo("git", repo, exportArgs);
        exportPsi.StandardOutputEncoding = null;
        var importPsi = Proc.StartInfo("git", repo, ["fast-import", "--force", "--quiet"]);
        importPsi.StandardOutputEncoding = null;

        using var export = new Process { StartInfo = exportPsi };
        using var import = new Process { StartInfo = importPsi };
        export.Start();
        import.Start();
        var exportErr = export.StandardError.ReadToEndAsync(ct);
        var importErr = import.StandardError.ReadToEndAsync(ct);
        var importOut = import.StandardOutput.ReadToEndAsync(ct);
        progress?.Report("Rewriting history…");
        try
        {
            await FilterAsync(export.StandardOutput.BaseStream, import.StandardInput.BaseStream, plan, ct);
        }
        catch
        {
            try { export.Kill(true); } catch { }
            try { import.Kill(true); } catch { }
            throw;
        }
        finally
        {
            try { import.StandardInput.Close(); } catch { }
        }
        await export.WaitForExitAsync(ct);
        await import.WaitForExitAsync(ct);
        await importOut;
        if (export.ExitCode != 0) throw new InvalidOperationException("git fast-export failed: " + (await exportErr).Trim());
        if (import.ExitCode != 0) throw new InvalidOperationException("git fast-import failed: " + (await importErr).Trim());

        progress?.Report("Updating your files…");
        if (!(await Git.RunAsync(repo, ct, "rev-parse", "--is-bare-repository")).StdOut.Trim().Equals("true", StringComparison.Ordinal))
            await Git.OutAsync(repo, ct, "reset", "--hard", "--quiet");

        progress?.Report("Cleaning old copies…");
        var expire = new List<string> { "reflog", "expire", "--expire=now", "--expire-unreachable=now", "HEAD" };
        expire.AddRange(refs);
        await Git.RunAsync(repo, ct, [.. expire]);
        await Git.RunAsync(repo, ct, "gc", "--prune=now", "--quiet");
    }

    internal static async Task FilterAsync(Stream input, Stream output, Plan plan, CancellationToken ct)
    {
        var replacer = new Replacer(plan.Replacements);
        var emails = new Dictionary<string, string>(plan.EmailMap, StringComparer.OrdinalIgnoreCase);
        var reader = new ByteReader(input);
        var bufOut = new BufferedStream(output, 1 << 16);
        var state = "";
        static byte[] B(string s) => Encoding.UTF8.GetBytes(s);
        async Task WriteLine(byte[] line)
        {
            await bufOut.WriteAsync(line, ct);
            bufOut.WriteByte((byte)'\n');
        }

        while (true)
        {
            var line = await reader.ReadLineAsync(ct);
            if (line is null) break;
            if (StartsWith(line, "data "))
            {
                var len = int.Parse(Encoding.ASCII.GetString(line, 5, line.Length - 5));
                var data = await reader.ReadExactAsync(len, ct);
                if (state == "blob") data = replacer.Data(data);
                else if (state is "commit" or "tag" && !replacer.IsEmpty) data = B(replacer.Text(Encoding.UTF8.GetString(data)));
                await WriteLine(B($"data {data.Length}"));
                await bufOut.WriteAsync(data, ct);
                continue;
            }
            if (StartsWith(line, "blob")) state = "blob";
            else if (StartsWith(line, "commit ")) state = "commit";
            else if (StartsWith(line, "tag ")) state = "tag";
            else if (StartsWith(line, "reset ")) state = "reset";
            else if (state is "commit" or "tag" && (StartsWith(line, "author ") || StartsWith(line, "committer ") || StartsWith(line, "tagger ")))
            {
                line = RewriteIdentity(line, emails, replacer);
            }
            else if (state == "commit" && plan.DropPaths.Count > 0 && (StartsWith(line, "M ") || StartsWith(line, "D ")))
            {
                var path = ParseChangePath(line);
                if (path is not null && plan.DropPaths.Contains(path)) continue;
            }
            await WriteLine(line);
        }
        await bufOut.FlushAsync(ct);
    }

    private static bool StartsWith(byte[] line, string prefix)
    {
        if (line.Length < prefix.Length) return false;
        for (var i = 0; i < prefix.Length; i++) if (line[i] != prefix[i]) return false;
        return true;
    }

    internal static byte[] RewriteIdentity(byte[] line, Dictionary<string, string> emails, Replacer replacer)
    {
        var s = Encoding.UTF8.GetString(line);
        var sp = s.IndexOf(' ');
        var lt = s.IndexOf(" <", StringComparison.Ordinal);
        var gt = s.IndexOf('>', lt + 2);
        if (sp < 0 || lt < sp || gt < 0) return line;
        var kind = s[..sp];
        var name = s[(sp + 1)..lt];
        var email = s[(lt + 2)..gt];
        var rest = s[(gt + 1)..];
        if (emails.TryGetValue(email, out var newEmail)) email = newEmail;
        name = replacer.Text(name);
        email = replacer.Text(email);
        return Encoding.UTF8.GetBytes($"{kind} {name} <{email}>{rest}");
    }

    /// <summary>"M mode dataref path" / "D path" (path may be C-style quoted).</summary>
    internal static string? ParseChangePath(byte[] line)
    {
        var s = Encoding.UTF8.GetString(line);
        string raw;
        if (s.StartsWith("D ", StringComparison.Ordinal)) raw = s[2..];
        else
        {
            var first = s.IndexOf(' ', 2);
            var second = first < 0 ? -1 : s.IndexOf(' ', first + 1);
            if (second < 0) return null;
            raw = s[(second + 1)..];
        }
        return raw.StartsWith('"') ? Unquote(raw) : raw;
    }

    internal static string Unquote(string q)
    {
        var bytes = new List<byte>();
        for (var i = 1; i < q.Length - 1; i++)
        {
            var c = q[i];
            if (c != '\\')
            {
                var chunk = char.IsHighSurrogate(c) && i + 1 < q.Length - 1 ? q.Substring(i++, 2) : c.ToString();
                bytes.AddRange(Encoding.UTF8.GetBytes(chunk));
                continue;
            }
            var n = q[++i];
            switch (n)
            {
                case 'n': bytes.Add((byte)'\n'); break;
                case 't': bytes.Add((byte)'\t'); break;
                case '"': bytes.Add((byte)'"'); break;
                case '\\': bytes.Add((byte)'\\'); break;
                case 'a': bytes.Add(7); break;
                case 'b': bytes.Add(8); break;
                case 'f': bytes.Add(12); break;
                case 'r': bytes.Add(13); break;
                case 'v': bytes.Add(11); break;
                default:
                    if (n is >= '0' and <= '7' && i + 2 < q.Length)
                    {
                        bytes.Add(Convert.ToByte(q.Substring(i, 3), 8));
                        i += 2;
                    }
                    else bytes.AddRange(Encoding.UTF8.GetBytes(n.ToString()));
                    break;
            }
        }
        return Encoding.UTF8.GetString(bytes.ToArray());
    }
}
