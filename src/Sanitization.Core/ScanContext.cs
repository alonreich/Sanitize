using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Sanitization.Core;

public sealed class ScanContext
{
    public PlaceholderMap Placeholders { get; }
    public OrgTerms Orgs { get; }

    public ScanContext(AppSettings settings)
    {
        Placeholders = new PlaceholderMap(settings.Placeholders);
        Orgs = new OrgTerms(settings.OrgTerms);
    }

    public static ScanContext Ephemeral() => new(new AppSettings());
}

public sealed class PlaceholderMap(Dictionary<string, string> store)
{
    private readonly object _lock = new();

    public static string Normalize(string kind, string value) => kind switch
    {
        "email" or "tenant" or "hex32" or "guid" or "org" => value.ToLowerInvariant(),
        "mac" => string.Concat(value.Where(char.IsAsciiHexDigit)).ToUpperInvariant(),
        "phone" => string.Concat(value.Where(char.IsAsciiDigit)),
        _ => value,
    };

    private static string Hash(string kind, string normalized) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(kind + "|" + normalized))).ToLowerInvariant();

    public string Get(string kind, string value)
    {
        var key = Hash(kind, Normalize(kind, value));
        lock (_lock)
        {
            if (store.TryGetValue(key, out var known)) return known;
            var used = new HashSet<string>(store.Values, StringComparer.OrdinalIgnoreCase);
            string candidate;
            var i = 0;
            do candidate = Candidate(kind, i++);
            while (used.Contains(kind + ":" + candidate) && i < 100_000);
            store[key] = kind + ":" + candidate;
            return kind + ":" + candidate;
        }
    }

    public string For(string kind, string value)
    {
        var tagged = Get(kind, value);
        return tagged[(kind.Length + 1)..];
    }

    internal static string Candidate(string kind, int i) => kind switch
    {
        "ipv4" => i < 245 ? $"203.0.113.{10 + i}" : i < 490 ? $"198.51.100.{10 + i - 245}" : $"203.0.113.{10 + i % 245}",
        "lan-ip" => $"192.0.2.{10 + i % 245}",
        "email" => i == 0 ? "user@example.com" : $"user{i + 1}@example.com",
        "phone" => i < 100 ? $"+1-555-01{i:00}" : $"+44 20 7946 0{(i - 100) % 1000:000}",
        "mac" => $"00:00:5E:00:53:{(i + 1) % 256:X2}",
        "tenant" or "org" => i switch { 0 => "contoso", 1 => "fabrikam", _ => $"contoso{i}" },
        "hex32" => (i + 1).ToString("x32"),
        "guid" => $"00000000-0000-0000-0000-{i + 1:x12}",
        "id" => $"REDACTED_ID_{i + 1}",
        _ => $"REDACTED_{i + 1}",
    };

    public static string FormatMac(string canonical, string original)
    {
        var hex = canonical.Replace(":", "");
        if (original.Length == 14 && original[4] == '.') return $"{hex[..4]}.{hex[4..8]}.{hex[8..]}".ToLowerInvariant();
        var sep = original.Length > 2 && !char.IsAsciiHexDigit(original[2]) ? original[2] : ':';
        return string.Join(sep, Enumerable.Range(0, 6).Select(k => hex.Substring(k * 2, 2)));
    }
}

public sealed partial class OrgTerms(List<string> store)
{
    private readonly object _lock = new();

    private static readonly HashSet<string> Webmail = new(StringComparer.OrdinalIgnoreCase)
    {
        "gmail", "googlemail", "outlook", "hotmail", "live", "msn", "yahoo", "ymail", "icloud", "me", "mac", "aol", "proton", "protonmail",
        "pm", "gmx", "mail", "yandex", "zoho", "fastmail", "tutanota", "hey", "walla", "bezeqint", "netvision", "012", "inter", "mailbox",
        "web", "t-online", "orange", "free", "comcast", "verizon", "att", "qq", "163", "126", "naver", "rediffmail", "seznam", "libero",
    };

    private static readonly HashSet<string> Brands = new(StringComparer.OrdinalIgnoreCase)
    {
        "microsoft", "google", "github", "gitlab", "bitbucket", "apple", "amazon", "amazonaws", "mozilla", "cloudflare", "openai", "anthropic",
        "facebook", "meta", "twitter", "linkedin", "slack", "atlassian", "jetbrains", "oracle", "adobe", "ibm", "intel", "nvidia", "mailchimp",
        "sendgrid", "stripe", "paypal", "docker", "npmjs", "nuget", "python", "apache", "debian", "ubuntu", "redhat", "kernel", "gnu", "w3",
        "jquery", "nodejs", "dotnet", "android", "chromium", "electron", "sentry", "heroku", "vercel", "netlify", "digicert", "letsencrypt",
        "verisign", "sectigo", "globalsign", "sourceforge", "readthedocs", "stackoverflow", "wikipedia", "unicode", "ietf", "iana",
        "example", "contoso", "fabrikam", "company", "domain", "corp", "group", "global", "cloud", "online", "info", "admin", "support",
        "service", "services", "home", "test", "demo", "local", "user", "users", "office", "email", "team", "noreply", "badsite",
    };

    private static readonly HashSet<string> SecondLevel = new(StringComparer.OrdinalIgnoreCase) { "co", "com", "org", "net", "ac", "gov", "edu", "or", "ne", "gv", "muni" };

    public IReadOnlyList<(string Label, string Domain)> All
    {
        get
        {
            lock (_lock)
                return store.Select(s => s.Split('|')).Where(p => p.Length == 2).Select(p => (p[0], p[1])).ToList();
        }
    }

    public static (string Label, string Domain)? FromEmail(string email)
    {
        var at = email.LastIndexOf('@');
        if (at < 0) return null;
        var labels = email[(at + 1)..].ToLowerInvariant().Split('.');
        if (labels.Length < 2) return null;
        var idx = labels.Length >= 3 && labels[^1].Length == 2 && SecondLevel.Contains(labels[^2]) ? labels.Length - 3 : labels.Length - 2;
        var label = labels[idx];
        if (label.Length < 4 || !label.Any(char.IsAsciiLetter) || Webmail.Contains(label) || Brands.Contains(label)) return null;
        return (label, string.Join('.', labels[idx..]));
    }

    public bool Learn(string email)
    {
        if (FromEmail(email) is not { } org) return false;
        var entry = org.Label + "|" + org.Domain;
        lock (_lock)
        {
            if (store.Contains(entry, StringComparer.OrdinalIgnoreCase)) return false;
            store.Add(entry);
            return true;
        }
    }

    public static string Replace(string token, string label, string domain)
    {
        var t = Regex.Replace(token, Regex.Escape(domain), "contoso.com", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        return Regex.Replace(t, Regex.Escape(label), m => m.Value.All(c => !char.IsLetter(c) || char.IsUpper(c)) && m.Value.Any(char.IsLetter) ? "CONTOSO"
            : char.IsUpper(m.Value[0]) ? "Contoso" : "contoso", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    }

    public static Rule BuildRule(string label, string domain) => new()
    {
        Category = "Your organisation's name (learned from an e-mail domain)", Severity = Severity.Medium,
        Regex = new Regex(@"(?<![A-Za-z0-9])[A-Za-z0-9-]*" + Regex.Escape(label) + @"[A-Za-z0-9-]*(?:\.[A-Za-z0-9-]+)*(?<![.-])(?![A-Za-z0-9])",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant),
        Why = $"Names the organisation behind the e-mail addresses at {domain} found in this project.",
        Replace = m => Replace(m.Value, label, domain),
    };
}

public static partial class OfficeText
{
    public static readonly HashSet<string> Extensions = new(StringComparer.OrdinalIgnoreCase) { ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm" };

    [GeneratedRegex(@"<(?:w:t|a:t|t)(?:\s[^>]*)?>([^<]*)</(?:w:t|a:t|t)>")]
    private static partial Regex TextRun();

    [GeneratedRegex(@"<(?:dc:creator|cp:lastModifiedBy|Company|Manager)>([^<]+)</")]
    private static partial Regex AuthorField();

    [GeneratedRegex(@"</(?:w:p|a:p|si|row|c)>")]
    private static partial Regex Break();

    private static readonly HashSet<string> GenericAuthors = new(StringComparer.OrdinalIgnoreCase)
    {
        "openpyxl", "python-docx", "python-pptx", "Microsoft Office User", "Microsoft Office", "User", "Author", "Unknown", "Administrator",
        "admin", "Windows User", "ClosedXML", "EPPlus", "NPOI", "Apache POI", "SheetJS", "xlsxwriter", "docx4j", "LibreOffice", "Google",
    };

    public static bool IsOffice(string path) => Extensions.Contains(Path.GetExtension(path));

    public static (string Text, List<string> Authors)? Extract(byte[] data)
    {
        try
        {
            using var zip = new ZipArchive(new MemoryStream(data), ZipArchiveMode.Read);
            var sb = new StringBuilder();
            var authors = new List<string>();
            foreach (var e in zip.Entries)
            {
                var n = e.FullName;
                var content = n.StartsWith("docProps/", StringComparison.OrdinalIgnoreCase) && n.EndsWith(".xml", StringComparison.OrdinalIgnoreCase);
                var body = n.EndsWith(".xml", StringComparison.OrdinalIgnoreCase) && (n.StartsWith("word/", StringComparison.OrdinalIgnoreCase)
                    || n.StartsWith("xl/sharedStrings", StringComparison.OrdinalIgnoreCase) || n.StartsWith("xl/worksheets/", StringComparison.OrdinalIgnoreCase)
                    || n.StartsWith("xl/comments", StringComparison.OrdinalIgnoreCase) || n.StartsWith("ppt/slides/", StringComparison.OrdinalIgnoreCase)
                    || n.StartsWith("ppt/notesSlides/", StringComparison.OrdinalIgnoreCase));
                if (!content && !body || e.Length > Scanner.MaxBytes) continue;
                using var r = new StreamReader(e.Open(), Encoding.UTF8);
                var xml = r.ReadToEnd();
                if (content)
                {
                    foreach (Match m in AuthorField().Matches(xml))
                    {
                        var a = WebUtility.HtmlDecode(m.Groups[1].Value).Trim();
                        if (a.Length >= 3 && !GenericAuthors.Contains(a) && !authors.Contains(a, StringComparer.OrdinalIgnoreCase)) authors.Add(a);
                    }
                    continue;
                }
                xml = Break().Replace(xml, m => m.Value + "\u0001");
                foreach (var chunk in xml.Split('\u0001'))
                {
                    var line = string.Concat(TextRun().Matches(chunk).Select(m => WebUtility.HtmlDecode(m.Groups[1].Value)));
                    if (line.Length > 0) sb.Append(line).Append('\n');
                }
            }
            return (sb.ToString(), authors);
        }
        catch
        {
            return null;
        }
    }

    public static bool LooksLikeName(string s) => RealName().IsMatch(s.Trim()) && !Heuristics.GenericUserNames.Contains(s.Trim());

    [GeneratedRegex(@"^(?:\p{Lu}[\p{Ll}'’-]+(?:\s+\p{Lu}\.?)?(?:\s+\p{Lu}[\p{Ll}'’-]+)+|[֐-׿'’-]{2,}(?:\s+[֐-׿'’-]{2,})+)$")]
    internal static partial Regex RealName();
}
