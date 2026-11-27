using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace Sanitization.Core;

/// <summary>
/// The HTML report is never written to disk: it is served once from memory over 127.0.0.1 with a random one-time
/// address and "Cache-Control: no-store" (the browser doesn't cache it either). After the browser loads it, the
/// server stops. Closing or reloading the tab makes it disappear for good.
/// </summary>
public static class Report
{
    public static string BuildHtml(string root, IReadOnlyList<ProjectScanResult> results, DateTime when)
    {
        var sb = new StringBuilder();
        static string E(string? s) => WebUtility.HtmlEncode(s ?? "");
        sb.Append("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"referrer\" content=\"no-referrer\">")
          .Append("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">")
          .Append("<title>Sanitization report</title><style>")
          .Append("body{background:#1e293b;color:#f1f5f9;font-family:Segoe UI,Inter,Arial,sans-serif;margin:0;padding:28px 36px}")
          .Append("h1{margin:0 0 4px;font-size:26px}.muted{color:#b6c2d0}.card{background:#273548;border:1px solid #475569;border-radius:12px;padding:18px 20px;margin:18px 0}")
          .Append("h2{margin:0 0 6px;font-size:21px}h3{margin:16px 0 6px;font-size:15px;padding-left:10px;border-left:5px solid}")
          .Append("table{border-collapse:collapse;width:100%;font-size:13px}td,th{padding:7px 9px;border-bottom:1px solid #3b4a60;text-align:left;vertical-align:top}")
          .Append("th{color:#b6c2d0;font-weight:600}code{font-family:Cascadia Mono,Consolas,monospace;color:#fde68a;word-break:break-all}")
          .Append(".chip{display:inline-block;padding:1px 8px;border-radius:9px;background:#334155;margin:1px 3px 1px 0;font-size:11px}")
          .Append(".c0{border-color:#ef4444}.c1{border-color:#f97316}.c2{border-color:#eab308}.c3{border-color:#94a3b8}.ok{color:#4ade80}")
          .Append("</style></head><body>");
        var total = results.Sum(r => r.Findings.Count);
        sb.Append($"<h1>Sanitization report</h1><div class=\"muted\">{E(root)} &middot; {when:yyyy-MM-dd HH:mm} &middot; {results.Count} projects &middot; {total} findings &middot; this page exists only in this tab</div>");
        foreach (var r in FindingOrdering.SortProjects(results))
        {
            sb.Append("<div class=\"card\">");
            sb.Append($"<h2>{E(r.Project.Name)}</h2><div class=\"muted\">{E(r.Project.Path)}{(r.Project.GitHub is null ? "" : " &middot; " + E(r.Project.GitHub.FullName))}</div>");
            if (r.Findings.Count == 0) { sb.Append("<p class=\"ok\">&#10004; Nothing found</p></div>"); continue; }
            foreach (var g in r.Findings.GroupBy(f => f.Severity).OrderBy(g => g.Key))
            {
                sb.Append($"<h3 class=\"c{(int)g.Key}\">{SeverityText.Title(g.Key)} &mdash; {g.Count()}</h3>");
                sb.Append("<table><tr><th>What</th><th>Value</th><th>Where</th><th>Fix</th></tr>");
                foreach (var f in FindingOrdering.Sort(g))
                {
                    var where = new StringBuilder();
                    where.Append(f.RelativePath.Length > 0 ? E(f.RelativePath) : "commit data");
                    if (f.Lines.Count > 0) where.Append(":" + string.Join(",", f.Lines.Take(8)));
                    where.Append("<br>");
                    foreach (var chip in SeverityText.Chips(f)) where.Append($"<span class=\"chip\">{E(chip)}</span>");
                    var value = f.Value.Length > 400 ? f.Value[..400] + "…" : f.Value;
                    sb.Append($"<tr><td><b>{E(f.Category)}</b><br><span class=\"muted\">{E(f.Why)}</span></td><td><code>{E(value)}</code></td><td>{where}</td><td>{E(f.CanFix || f.OnlyOnRemote ? f.FixDescription : f.NoFixReason)}{(f.Replacement is null ? "" : "<br>&rarr; <code>" + E(f.Replacement) + "</code>")}</td></tr>");
                }
                sb.Append("</table>");
            }
            sb.Append("</div>");
        }
        sb.Append("</body></html>");
        return sb.ToString();
    }

    /// <summary>Starts a one-shot loopback server and returns the URL. The server stops after one page load or 2 minutes.</summary>
    public static string ServeOnce(string html)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(24)).ToLowerInvariant();
        var body = Encoding.UTF8.GetBytes(html);
        _ = Task.Run(async () =>
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(2));
            try
            {
                while (!cts.IsCancellationRequested)
                {
                    using var client = await listener.AcceptTcpClientAsync(cts.Token);
                    await using var stream = client.GetStream();
                    var buf = new byte[8192];
                    var n = await stream.ReadAsync(buf, cts.Token);
                    var request = Encoding.ASCII.GetString(buf, 0, n);
                    var firstLine = request.Split("\r\n")[0];
                    var ok = firstLine.StartsWith($"GET /{token} ", StringComparison.Ordinal);
                    var payload = ok ? body : "Gone."u8.ToArray();
                    var header = $"HTTP/1.1 {(ok ? "200 OK" : "404 Not Found")}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {payload.Length}\r\n" +
                                 "Cache-Control: no-store, no-cache, must-revalidate\r\nPragma: no-cache\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n";
                    await stream.WriteAsync(Encoding.ASCII.GetBytes(header), cts.Token);
                    await stream.WriteAsync(payload, cts.Token);
                    if (ok) break;
                }
            }
            catch { }
            finally
            {
                listener.Stop();
                CryptographicOperations.ZeroMemory(body);
            }
        });
        return $"http://127.0.0.1:{port}/{token}";
    }

    public static void OpenInBrowser(string url)
    {
        string[] chromes =
        [
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"Google\Chrome\Application\chrome.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), @"Google\Chrome\Application\chrome.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Google\Chrome\Application\chrome.exe"),
        ];
        var chrome = chromes.FirstOrDefault(File.Exists);
        if (chrome is not null)
        {
            var psi = new ProcessStartInfo(chrome) { UseShellExecute = false };
            psi.ArgumentList.Add(url);
            Process.Start(psi);
        }
        else Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
    }
}

public static class SeverityText
{
    public static string Title(Severity s) => s switch
    {
        Severity.Critical => "Critical",
        Severity.High => "High",
        Severity.Medium => "Medium",
        _ => "Probably fine",
    };

    public static string Subtitle(Severity s) => s switch
    {
        Severity.Critical => "Passwords, keys and tokens. Fix these first.",
        Severity.High => "Things that identify you: your e-mail, name, PC, user name.",
        Severity.Medium => "IP addresses, host names, other people's e-mails. Check each one.",
        _ => "Probably test or sample data. Glance over them, no rush.",
    };

    public static IEnumerable<string> Chips(Finding f)
    {
        if (f.Kind == FindingKind.CommitIdentity) yield return $"in {f.CommitMessages.Count} commit(s)";
        if (f.Kind == FindingKind.RemoteUrl) yield return "git settings";
        if (f.InWorkingTree)
        {
            yield return f.Lines.Count > 0 ? $"File · line {string.Join(", ", f.Lines.Take(5))}{(f.Lines.Count > 5 ? "…" : "")}" : "File";
            if (f.FileState == FileState.Ignored) yield return "Never committed (in .gitignore)";
            if (f.FileState == FileState.Untracked) yield return "Not committed yet";
            if (f.FileState == FileState.NotGit) yield return "Not in git";
        }
        if (f.HistoryVersions > 0) yield return $"Git history · {f.HistoryVersions} version{(f.HistoryVersions == 1 ? "" : "s")}";
        if (f.Kind == FindingKind.TextValue && f.CommitMessages.Count > 0) yield return $"Commit message ×{f.CommitMessages.Count}";
        if (f.OnRemote) yield return "On GitHub";
        if (f.OnlyOnRemote) yield return "Removed here · push to finish";
    }
}
