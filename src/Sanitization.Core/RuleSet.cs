using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;

namespace Sanitization.Core;

/// <summary>Who "you" are on this PC, detected automatically.</summary>
public sealed class MachineIdentity
{
    public string UserName { get; init; } = "";
    public string MachineName { get; init; } = "";
    public string DnsDomain { get; init; } = "";
    public string Fqdn { get; init; } = "";
    public string Sid { get; init; } = "";
    public string GlobalGitEmail { get; init; } = "";
    public List<string> LanIps { get; init; } = [];

    public static async Task<MachineIdentity> DetectAsync(CancellationToken ct = default)
    {
        var machine = Environment.MachineName;
        string fqdn = "";
        try
        {
            var host = (await Dns.GetHostEntryAsync("", ct)).HostName;
            if (!string.Equals(host, machine, StringComparison.OrdinalIgnoreCase)) fqdn = host;
        }
        catch { }
        string sid = "";
        try { sid = WindowsIdentity.GetCurrent().User?.Value ?? ""; } catch { }
        var ips = new List<string>();
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                {
                    if (ua.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                    var ip = ua.Address.ToString();
                    if (!ip.StartsWith("127.") && !ip.StartsWith("169.254.") && !ip.EndsWith(".1") && !ip.EndsWith(".0") && !ip.EndsWith(".255")) ips.Add(ip);
                }
            }
        }
        catch { }
        var email = (await Git.TryOutAsync(Environment.CurrentDirectory, ct, "config", "--global", "user.email")).Trim();
        return new MachineIdentity
        {
            UserName = Environment.UserName,
            MachineName = machine,
            DnsDomain = Environment.GetEnvironmentVariable("USERDNSDOMAIN") ?? "",
            Fqdn = fqdn,
            Sid = sid,
            GlobalGitEmail = email,
            LanIps = ips.Distinct().ToList(),
        };
    }
}

public enum Verdict { Drop, Keep, Low }

public sealed class Rule
{
    public required string Category { get; init; }
    public required Regex Regex { get; init; }
    public required Severity Severity { get; init; }
    public required string Why { get; init; }
    public Func<Match, string>? Replace { get; init; }
    public Func<Match, string, string, Verdict>? Validate { get; init; }
    /// <summary>Also looked for inside binaries that are tracked in git.</summary>
    public bool Binary { get; init; }
    /// <summary>Generic (not about you): downgraded to Low inside test / vendored files.</summary>
    public bool Generic { get; init; }
    /// <summary>Group that holds the value to report (0 = whole match).</summary>
    public int ValueGroup { get; init; }
}

public sealed record Hit(Rule Rule, string Value, string? Replacement, int Index, Severity Severity);

public sealed class RuleSet
{
    public const string WhySecret = "Anyone who sees this can use the account or service it belongs to.";

    /// <summary>"chrome.storage.local" and friends are code, not host names.</summary>
    private static readonly HashSet<string> CodeRoots = new(StringComparer.OrdinalIgnoreCase)
    {
        "chrome", "browser", "window", "this", "self", "process", "os", "storage", "settings", "config", "app", "document", "navigator",
        "context", "ctx", "options", "env", "data", "state", "props", "req", "res", "scope", "system", "global", "globalthis", "module",
        "exports", "localstorage", "sessionstorage", "vm", "model", "host", "server", "my", "your", "foo", "bar",
    };
    private readonly List<Rule> _rules = [];
    private readonly HashSet<string> _ignored;
    public IReadOnlyList<Rule> Rules => _rules;
    public IReadOnlyList<Rule> BinaryRules { get; }
    public MachineIdentity Identity { get; }

    public RuleSet(MachineIdentity id, IEnumerable<PrivateTerm> privateTerms, IEnumerable<string> extraGitEmails, IEnumerable<string>? ignoredValues = null)
    {
        Identity = id;
        _ignored = new HashSet<string>(ignoredValues ?? [], StringComparer.OrdinalIgnoreCase);
        const RegexOptions ci = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;

        foreach (var t in privateTerms.Where(t => t.Value.Trim().Length >= 3))
        {
            var repl = string.IsNullOrWhiteSpace(t.Replacement) ? "REDACTED" : t.Replacement;
            _rules.Add(new Rule { Category = "Your private info", Regex = new Regex(Heuristics.Bounded(t.Value.Trim()), ci), Severity = Severity.High,
                Why = "You listed this in \"My private info\".", Replace = _ => repl, Binary = true });
        }
        if (id.UserName.Length >= 3 && !Heuristics.GenericUserNames.Contains(id.UserName))
        {
            _rules.Add(new Rule { Category = "Your Windows user name (in a path)", Severity = Severity.High,
                Regex = new Regex(@"((?<![A-Za-z0-9])(?:Users|home|Documents and Settings)[\\/]+)(" + Regex.Escape(id.UserName) + ")(?![A-Za-z0-9])", ci),
                Why = "Reveals the user name you log in to Windows with.", Replace = m => m.Groups[1].Value + "USERNAME", Binary = true });
            if (id.MachineName.Length >= 3)
                _rules.Add(new Rule { Category = "Your PC and user name", Severity = Severity.High,
                    Regex = new Regex(Heuristics.Bounded(id.MachineName) + @"(\\+)" + Regex.Escape(id.UserName) + "(?![A-Za-z0-9])", ci),
                    Why = "Reveals your computer name and Windows user name.", Replace = m => "MY-PC" + m.Groups[1].Value + "USERNAME", Binary = true });
        }
        if (id.MachineName.Length >= 3)
            _rules.Add(new Rule { Category = "Your computer name", Severity = Severity.High, Regex = new Regex(Heuristics.Bounded(id.MachineName), ci),
                Why = "Identifies your PC on networks and in logs.", Replace = _ => "MY-PC", Binary = true });
        if (id.Fqdn.Length >= 3)
            _rules.Add(new Rule { Category = "Your computer's full network name", Severity = Severity.High, Regex = new Regex(Heuristics.Bounded(id.Fqdn), ci),
                Why = "Identifies your PC and network.", Replace = _ => "my-pc.example.com", Binary = true });
        if (id.DnsDomain.Length >= 3)
            _rules.Add(new Rule { Category = "Your network domain", Severity = Severity.High, Regex = new Regex(Heuristics.Bounded(id.DnsDomain), ci),
                Why = "Identifies your organisation's network.", Replace = _ => "corp.example.com", Binary = true });
        if (id.Sid.Length > 0)
            _rules.Add(new Rule { Category = "Your Windows account ID (SID)", Severity = Severity.High, Regex = new Regex(Heuristics.Bounded(id.Sid)),
                Why = "Uniquely identifies your Windows account.", Replace = _ => "S-1-5-21-1000000000-2000000000-3000000000-1001", Binary = true });
        foreach (var e in extraGitEmails.Append(id.GlobalGitEmail).Where(e => e.Contains('@') && !e.Contains("noreply", StringComparison.OrdinalIgnoreCase)).Distinct(StringComparer.OrdinalIgnoreCase))
            _rules.Add(new Rule { Category = "Your git e-mail", Severity = Severity.High, Regex = new Regex(Heuristics.Bounded(e), ci),
                Why = "Your real e-mail address, as configured in git.", Replace = _ => "user@example.com", Binary = true });

        AddSecret("AWS access key", Patterns.AwsKey());
        AddSecret("GitHub token", Patterns.GitHubToken());
        AddSecret("Slack token", Patterns.SlackToken());
        AddSecret("Google API key", Patterns.GoogleKey());
        AddSecret("OpenAI / Anthropic API key", Patterns.OpenAiKey());
        AddSecret("Stripe live key", Patterns.StripeKey());
        AddSecret("Telegram bot token", Patterns.TelegramToken());
        AddSecret("Webhook URL with secret", Patterns.WebhookUrl());
        AddSecret("Azure storage key", Patterns.AzureStorageKey());
        AddSecret("npm token", Patterns.NpmToken());
        AddSecret("Hugging Face token", Patterns.HuggingFaceToken());
        _rules.Add(new Rule { Category = "Login token (JWT)", Regex = Patterns.Jwt(), Severity = Severity.Critical, Why = WhySecret,
            Replace = _ => "REDACTED_SECRET", Validate = ValidateJwt });
        _rules.Add(new Rule { Category = "Private key", Regex = Patterns.PrivateKeyBlock(), Severity = Severity.Critical,
            Why = "Lets others sign, decrypt or log in as you.", Replace = _ => "-----BEGIN PRIVATE KEY-----\nREDACTED\n-----END PRIVATE KEY-----",
            Validate = (m, _, _) => m.Groups[3].Value.Trim().Length < 64 || Patterns.KeyBodyPlaceholder().IsMatch(m.Groups[3].Value) ? Verdict.Drop : Verdict.Keep });
        _rules.Add(new Rule { Category = "Password inside a URL", Regex = Patterns.UrlCredentials(), Severity = Severity.Critical, Why = WhySecret,
            Replace = m => m.Groups[1].Value + "USER:PASSWORD@", Validate = ValidateUrlCredentials });
        _rules.Add(new Rule { Category = "Password / secret in code", Regex = Patterns.PasswordAssignment(), Severity = Severity.Critical, Why = WhySecret,
            ValueGroup = 2, Replace = _ => "REDACTED_SECRET", Validate = ValidateAssignment, Generic = true });

        _rules.Add(new Rule { Category = "Someone's user name (in a path)", Regex = Patterns.OtherProfilePath(), Severity = Severity.Medium, Generic = true,
            Why = "A path that contains a person's user name.", Replace = m => m.Value[..(m.Groups[1].Index - m.Index)] + "USERNAME",
            Validate = (m, _, _) => Heuristics.GenericUserNames.Contains(m.Groups[1].Value.Trim()) || m.Groups[1].Value.Contains('%') ? Verdict.Drop : Verdict.Keep });
        _rules.Add(new Rule { Category = "E-mail address", Regex = Patterns.Email(), Severity = Severity.Medium, Generic = true,
            Why = "Someone's e-mail address. Check whether it is real.", Replace = _ => "user@example.com", Validate = ValidateEmail });
        _rules.Add(new Rule { Category = "Public IP address", Regex = Patterns.IPv4(), Severity = Severity.Medium, Generic = true, ValueGroup = 1,
            Why = "A real internet address. It can point to you or to a private server.", Replace = _ => "203.0.113.10", Validate = ValidateIp });
        foreach (var ip in id.LanIps)
            _rules.Add(new Rule { Category = "Your PC's local IP address", Regex = new Regex(Heuristics.Bounded(ip)), Severity = Severity.Medium,
                Why = "The address of this PC on your home / office network.", Replace = _ => "192.0.2.10" });
        _rules.Add(new Rule { Category = "Internal host name", Regex = Patterns.InternalHost(), Severity = Severity.Low, Generic = true, ValueGroup = 1,
            Why = "Names a machine on a private network.", Replace = _ => "host.example.internal",
            Validate = (m, _, _) => CodeRoots.Contains(m.Groups[1].Value.Split('.')[0]) || m.Groups[1].Value.StartsWith("example.", StringComparison.Ordinal) ? Verdict.Drop : Verdict.Keep });

        BinaryRules = _rules.Where(r => r.Binary).ToList();
    }

    private void AddSecret(string category, Regex rx) => _rules.Add(new Rule
    {
        Category = category, Regex = rx, Severity = Severity.Critical, Why = WhySecret, Replace = _ => "REDACTED_SECRET",
        Validate = (m, _, _) => Heuristics.LooksPlaceholder(m.Value) ? Verdict.Drop : Heuristics.HighEntropy(m.Value) ? Verdict.Keep : Verdict.Low,
    });

    private static Verdict ValidateJwt(Match m, string text, string path)
    {
        var payload = "";
        try
        {
            var seg = m.Value.Split('.')[1].Replace('-', '+').Replace('_', '/');
            seg = seg.PadRight(seg.Length + (4 - seg.Length % 4) % 4, '=');
            payload = Encoding.UTF8.GetString(Convert.FromBase64String(seg));
        }
        catch { }
        if (Heuristics.LooksPlaceholder(payload) || Patterns.JwtSamplePayload().IsMatch(payload)) return Verdict.Drop;
        return Heuristics.LooksPlaceholder(m.Value) ? Verdict.Drop : Heuristics.HighEntropy(m.Value) ? Verdict.Keep : Verdict.Low;
    }

    private static Verdict ValidateUrlCredentials(Match m, string text, string path)
    {
        var pw = m.Groups[3].Value;
        if ("$%{<[(".Contains(pw[0]) || Heuristics.LooksPlaceholder(pw) && pw.Length < 12) return Verdict.Drop;
        return Heuristics.HighEntropy(pw) || pw.Length >= 8 ? Verdict.Keep : Verdict.Low;
    }

    private static Verdict ValidateAssignment(Match m, string text, string path)
    {
        var v = m.Groups[2].Value;
        if (Heuristics.LooksPlaceholder(v) || Patterns.LettersOnly().IsMatch(v) || Patterns.CallExpression().IsMatch(v)) return Verdict.Drop;
        return Heuristics.HighEntropy(v) && v.Length >= 10 ? Verdict.Keep : Verdict.Low;
    }

    private static Verdict ValidateEmail(Match m, string text, string path)
    {
        var v = m.Value;
        var tld = v[(v.LastIndexOf('.') + 1)..];
        return Patterns.HarmlessEmail().IsMatch(v) || Heuristics.FileExtensionTlds.Contains(tld) ? Verdict.Drop : Verdict.Keep;
    }

    private static Verdict ValidateIp(Match m, string text, string path)
    {
        var ip = m.Groups[1].Value;
        if (Heuristics.WellKnownPublicIps.Contains(ip) || (path.Length > 0 && Patterns.IpNoisePath().IsMatch(path))) return Verdict.Drop;
        var start = Math.Max(0, m.Index - 25);
        if (Patterns.VersionPrefix().IsMatch(text.AsSpan(start, m.Index - start).ToString())) return Verdict.Drop;
        return Heuristics.IsPublicIp(ip) ? Verdict.Keep : Verdict.Drop;
    }

    public bool IsIgnored(string value) => _ignored.Contains(value);

    /// <summary>All hits in a text, overlaps resolved (most severe, then longest wins).</summary>
    public List<Hit> ScanText(string text, string path)
    {
        var lowContext = path.Length > 0 && (Patterns.TestPath().IsMatch(path) || Patterns.VendorPath().IsMatch(path));
        var candidates = new List<(int Start, int End, Hit Hit)>();
        foreach (var rule in _rules)
        {
            foreach (Match m in rule.Regex.Matches(text))
            {
                Group group = rule.ValueGroup > 0 ? m.Groups[rule.ValueGroup] : m;
                var value = group.Value;
                if (value.Length == 0 || IsIgnored(value)) continue;
                var verdict = rule.Validate?.Invoke(m, text, path) ?? Verdict.Keep;
                if (verdict == Verdict.Drop) continue;
                var sev = verdict == Verdict.Low || (rule.Generic && lowContext) ? Severity.Low : rule.Severity;
                candidates.Add((group.Index, group.Index + value.Length, new Hit(rule, value, rule.Replace?.Invoke(m), group.Index, sev)));
            }
        }
        candidates.Sort((a, b) =>
        {
            var c = a.Hit.Severity.CompareTo(b.Hit.Severity);
            if (c != 0) return c;
            c = (b.End - b.Start).CompareTo(a.End - a.Start);
            return c != 0 ? c : a.Start.CompareTo(b.Start);
        });
        var taken = new List<(int S, int E)>();
        var hits = new List<Hit>();
        foreach (var (s, e, h) in candidates)
        {
            var overlap = false;
            foreach (var (ts, te) in taken)
                if (s < te && ts < e) { overlap = true; break; }
            if (overlap) continue;
            taken.Add((s, e));
            hits.Add(h);
        }
        return hits;
    }

    /// <summary>Your identity embedded in a binary (ASCII or UTF-16LE text inside the file).</summary>
    public List<Rule> ScanBinary(byte[] data)
    {
        var found = new List<Rule>();
        if (BinaryRules.Count == 0) return found;
        string[] views = [Encoding.Latin1.GetString(data), Encoding.Unicode.GetString(data), data.Length > 1 ? Encoding.Unicode.GetString(data, 1, data.Length - 1) : ""];
        foreach (var r in BinaryRules)
            foreach (var v in views)
            {
                var m = r.Regex.Match(v);
                if (m.Success && !IsIgnored(m.Value)) { found.Add(r); break; }
            }
        return found;
    }
}
