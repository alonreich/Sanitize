using System.Text.RegularExpressions;

namespace Sanitization.Core;

internal static partial class Patterns
{
    [GeneratedRegex(@"(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])")]
    internal static partial Regex AwsKey();

    [GeneratedRegex(@"(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})")]
    internal static partial Regex GitHubToken();

    [GeneratedRegex(@"(?<![A-Za-z0-9])xox[abposr]-[A-Za-z0-9-]{10,200}")]
    internal static partial Regex SlackToken();

    [GeneratedRegex(@"(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_-]{35}(?![A-Za-z0-9_-])")]
    internal static partial Regex GoogleKey();

    [GeneratedRegex(@"(?<![A-Za-z0-9_-])sk-(?:ant-[a-z0-9]{2,8}-|proj-|live-)?[A-Za-z0-9_-]{20,200}")]
    internal static partial Regex OpenAiKey();

    [GeneratedRegex(@"(?<![A-Za-z0-9])[sr]k_live_[A-Za-z0-9]{16,200}")]
    internal static partial Regex StripeKey();

    [GeneratedRegex(@"(?<![0-9A-Za-z])\d{8,10}:AA[A-Za-z0-9_-]{33}(?![A-Za-z0-9_-])")]
    internal static partial Regex TelegramToken();

    [GeneratedRegex(@"https://(?:discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]{30,}|hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[A-Za-z0-9]{20,})")]
    internal static partial Regex WebhookUrl();

    [GeneratedRegex(@"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{15,}\.eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{20,}")]
    internal static partial Regex Jwt();

    [GeneratedRegex(@"AccountKey=[A-Za-z0-9+/]{80,}={0,2}")]
    internal static partial Regex AzureStorageKey();

    [GeneratedRegex(@"(?<![A-Za-z0-9])npm_[A-Za-z0-9]{36}(?![A-Za-z0-9])")]
    internal static partial Regex NpmToken();

    [GeneratedRegex(@"(?<![A-Za-z0-9])hf_[A-Za-z0-9]{34,}(?![A-Za-z0-9])")]
    internal static partial Regex HuggingFaceToken();

    [GeneratedRegex(@"-----BEGIN ((?:[A-Z0-9]+ )*)PRIVATE KEY( BLOCK)?-----([\s\S]{20,}?)-----END \1PRIVATE KEY\2-----")]
    internal static partial Regex PrivateKeyBlock();

    [GeneratedRegex(@"(?i)\b([a-z][a-z0-9+.-]{1,15}://)([^\s/:@'""<>]{1,64}):([^\s/@'""<>]{3,128})@(?=[A-Za-z0-9.-]+)")]
    internal static partial Regex UrlCredentials();

    [GeneratedRegex(@"(?i)(?<![A-Za-z0-9_])(password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|bot[_-]?token)[""']?\s*[:=]\s*[""']([^""'\s]{6,200})[""']")]
    internal static partial Regex PasswordAssignment();

    [GeneratedRegex(@"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?![A-Za-z0-9])")]
    internal static partial Regex Email();

    [GeneratedRegex(@"(?<![\w.\\/-])((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})(?![\w\\/-]|\.\d)")]
    internal static partial Regex IPv4();

    [GeneratedRegex(@"(?i)(?:\b[A-Za-z]:[\\/]+|(?<![A-Za-z0-9._-])[\\/]+)(?:Users|home)[\\/]+([A-Za-z0-9][A-Za-z0-9._ -]{1,30}?)(?=[\\/""'\s]|$)")]
    internal static partial Regex OtherProfilePath();

    [GeneratedRegex(@"(?<![A-Za-z0-9._-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,}(?:local|lan|corp|internal|intranet|localdomain))(?![A-Za-z0-9_-]|\.[A-Za-z_(]|\s*[(\[=])")]
    internal static partial Regex InternalHost();

    [GeneratedRegex(@"(?i)(^|/)(tests?|specs?|__tests__|fixtures?|testdata|test-data|samples?|examples?|mocks?)(/|$)|[._-](tests?|spec)\.[a-z0-9]+$|tests?\.cs$|_test\.(go|py)$|(^|/)test_[^/]*\.py$")]
    internal static partial Regex TestPath();

    [GeneratedRegex(@"(?i)(\.min\.(js|css)$|(^|/)(vendor|third[_-]?party|node_modules|bower_components)/|(^|/)(LICENSE|NOTICE|THIRD_PARTY_NOTICES|COPYING)[^/]*$|(^|/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|packages\.lock\.json)$)")]
    internal static partial Regex VendorPath();

    [GeneratedRegex(@"(?i)(^|/)(\.env(\.(?!example$|sample$|template$|dist$|defaults?$)[^/]+)?|id_(rsa|dsa|ecdsa|ed25519)|credentials\.json|secrets?\.json|client_secrets?[^/]*\.json|service[-_]account[^/]*\.json|[^/]+\.(key|pfx|p12|jks|keystore|kdbx|ppk|dmp|mdmp|har|pcap|pcapng|evtx|etl|publishsettings|ovpn))$")]
    internal static partial Regex SensitiveFileName();

    [GeneratedRegex(@"(?i)(users\.noreply\.github\.com$|^(no-?reply|noreply\+?[^@]*)@|^git@(github|gitlab|bitbucket)\.|@([a-z0-9-]+\.)*(example|localhost|test|invalid|local|domain|yourdomain|mydomain|company|contoso|fabrikam|email|acme)\.[a-z.]+$|\.(test|invalid|example|localhost|local)$|^(user|name|someone|john\.?doe|jane\.?doe|you|me|first\.last|firstname\.lastname)@)")]
    internal static partial Regex HarmlessEmail();

    [GeneratedRegex(@"(?i)(lock|version[^/]*$|\.csproj|\.props|\.nuspec|\.deps\.json|\.vcxproj|\.sln|assemblyinfo)")]
    internal static partial Regex IpNoisePath();

    [GeneratedRegex(@"(?i)\b(version|ver|v|build|release|rev)\W{0,3}$")]
    internal static partial Regex VersionPrefix();

    [GeneratedRegex(@"(?i)^(?:some(?:thing|one|where)?|any(?:thing)?|my[-_]?\w*|your[-_]?\w*|the[-_]?\w*|instance\w*|tenant\w*|company\w*|org(?:name)?|x+|y+|z+|abc\w*|foo\w*|bar)$")]
    internal static partial Regex PlaceholderSubdomain();

    [GeneratedRegex(@"(?:[A-Za-z][\w-]*\.)+[A-Za-z][\w-]*\s+$")]
    internal static partial Regex PackageIdBefore();

    [GeneratedRegex(@"(?<![0-9A-Fa-f-])[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}(?![0-9A-Fa-f-])|(?<![0-9A-Fa-f])(?=[0-9]*[A-Fa-f])[0-9A-Fa-f]{16,}(?![0-9A-Fa-f])")]
    internal static partial Regex IdLike();

    [GeneratedRegex(@"(?i)(?<![\w.-])([a-z0-9][a-z0-9-]{1,62})\.(service-now\.com|servicenowservices\.com|okta\.com|oktapreview\.com|okta-emea\.com|onelogin\.com|auth0\.com|my\.salesforce\.com|lightning\.force\.com|sharepoint\.com|onmicrosoft\.com|atlassian\.net|zendesk\.com|freshservice\.com|freshdesk\.com|slack\.com|webex\.com|zoom\.us|workday\.com|egnyte\.com|box\.com|guardicore\.com|crowdstrike\.com|sentinelone\.net|lightning\.force\.com|my\.site\.com|kandji\.io|jamfcloud\.com|pagerduty\.com|opsgenie\.com)(?![\w-])")]
    internal static partial Regex SaasTenant();

    [GeneratedRegex(@"(?i)(?<![A-Za-z])(?:tenant|customer|subscription|directory|organi[sz]ation|org)[ _-]?(?:id|name|no)?(?![A-Za-z])[""']?\s*[:=]\s*[""']?([A-Za-z0-9][A-Za-z0-9._-]{5,63})")]
    internal static partial Regex TenantId();

    [GeneratedRegex(@"(?i)(?:sys_id|sys_domain|assignment_group|caller_id|opened_by|assigned_to|company|location|sysparm_[a-z_]+)(?:!?=|!?%3D|!?%253D)([0-9a-f]{32})(?![0-9a-f])")]
    internal static partial Regex RecordId();

    [GeneratedRegex(@"(?i)\.\.\.|redacted|example|placeholder|your|x{6,}")]
    internal static partial Regex KeyBodyPlaceholder();

    [GeneratedRegex(@"(?i)john doe|jane doe|""sub"":\s*""(user|test|1234567890)""")]
    internal static partial Regex JwtSamplePayload();

    [GeneratedRegex(@"(.)\1{5,}")]
    internal static partial Regex RepeatedChar();

    [GeneratedRegex(@"^[A-Za-z_ .-]+$")]
    internal static partial Regex LettersOnly();

    [GeneratedRegex(@"^[A-Za-z_][A-Za-z0-9_.]*\(.*")]
    internal static partial Regex CallExpression();

    [GeneratedRegex(@"^(?:https?://|git@|ssh://git@)github\.com[:/]([^/]+)/([^/\s]+?)(?:\.git)?/?$", RegexOptions.IgnoreCase)]
    internal static partial Regex GitHubRemote();
}

internal static class Heuristics
{
    private static readonly string[] PlaceholderWords =
    [
        "example", "sample", "dummy", "fake", "test", "placeholder", "your", "xxxx", "abcdef", "0123", "1234",
        "redacted", "changeme", "change_me", "replace", "insert", "secret_here", "token_here", "<", ">", "{", "}",
        "$", "...", "****", "todo", "foobar", "lorem",
    ];

    internal static readonly HashSet<string> GenericUserNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "public", "default", "default user", "all users", "username", "user", "users", "runneradmin", "runner",
        "appveyor", "vsts", "vssadmin", "administrator", "admin", "me", "you", "yourname", "your_user",
        "yourusername", "john", "jane", "johndoe", "someone", "test", "name", "foo", "bar", "example", "dev",
        "developer", "ubuntu", "root", "node", "app", "vagrant", "shared", "guest", "defaultapppool",
        "alice", "bob", "carol", "dave", "eve", "mallory", "jdoe", "testuser", "user1", "user2",
    };

    internal static readonly HashSet<string> FileExtensionTlds = new(StringComparer.OrdinalIgnoreCase)
    {
        "png", "jpg", "jpeg", "gif", "svg", "ico", "js", "ts", "css", "json", "xml", "dll", "exe", "md", "txt",
        "html", "cs", "py", "ps1", "webp", "bmp", "mp3", "mp4", "wav", "zip", "pdb", "map",
    };

    internal static readonly HashSet<string> GenericSubdomains = new(StringComparer.OrdinalIgnoreCase)
    {
        "www", "login", "api", "auth", "app", "apps", "status", "support", "help", "docs", "developer", "developers", "community", "admin",
        "my", "portal", "signin", "accounts", "account", "cdn", "static", "mail", "events", "blog", "trust", "store", "marketplace", "partner",
        "partners", "university", "learning", "news", "investors", "go", "info", "instance", "tenant", "company", "yourcompany", "yourinstance",
        "yourorg", "your-org", "mycompany", "acme", "contoso", "fabrikam", "example", "sample", "demo", "test", "dev", "devportal",
    };

    internal static readonly HashSet<string> WellKnownPublicIps = new(StringComparer.Ordinal)
    {
        "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220",
    };

    internal static bool AscendingRun(string s, int n = 5)
    {
        var run = 1;
        for (var i = 1; i < s.Length; i++)
        {
            run = s[i] == s[i - 1] + 1 ? run + 1 : 1;
            if (run >= n) return true;
        }
        return false;
    }

    internal static string AlnumOnly(string v) => string.Concat(v.Where(char.IsAsciiLetterOrDigit));

    internal static bool LooksPlaceholder(string v)
    {
        var lv = v.ToLowerInvariant();
        foreach (var w in PlaceholderWords)
            if (lv.Contains(w, StringComparison.Ordinal)) return true;
        var core = AlnumOnly(v);
        if (core.Distinct().Count() < 8 || Patterns.RepeatedChar().IsMatch(core)) return true;
        return AscendingRun(string.Concat(lv.Where(char.IsAsciiLetterLower))) || AscendingRun(string.Concat(v.Where(char.IsAsciiDigit)));
    }

    internal static double Entropy(string s)
    {
        if (s.Length == 0) return 0;
        double e = 0;
        foreach (var g in s.GroupBy(c => c))
        {
            var p = (double)g.Count() / s.Length;
            e -= p * Math.Log2(p);
        }
        return e;
    }

    internal static bool HighEntropy(string v)
    {
        var core = AlnumOnly(v);
        var classes = (core.Any(char.IsAsciiLetterLower) ? 1 : 0) + (core.Any(char.IsAsciiLetterUpper) ? 1 : 0) + (core.Any(char.IsAsciiDigit) ? 1 : 0);
        return classes >= 2 && Entropy(core) >= 3.0;
    }

    internal static bool IsPublicIp(string ip)
    {
        var o = ip.Split('.').Select(int.Parse).ToArray();
        if (o[0] is 0 or 10 or 127 || o[0] >= 224) return false;
        if ((o[0] == 100 && o[1] is >= 64 and <= 127) || (o[0] == 169 && o[1] == 254) || (o[0] == 172 && o[1] is >= 16 and <= 31)) return false;
        if ((o[0] == 192 && o[1] == 168) || (o[0] == 192 && o[1] == 0 && o[2] is 0 or 2)) return false;
        if ((o[0] == 198 && (o[1] is 18 or 19 || (o[1] == 51 && o[2] == 100))) || (o[0] == 203 && o[1] == 0 && o[2] == 113)) return false;
        return !(o[1] == 0 && o[2] == 0 && o[3] == 0);
    }

    internal static string Bounded(string term)
    {
        var p = Regex.Escape(term);
        if (term.Length > 0 && char.IsLetterOrDigit(term[0])) p = "(?<![A-Za-z0-9])" + p;
        if (term.Length > 0 && char.IsLetterOrDigit(term[^1])) p += "(?![A-Za-z0-9])";
        return p;
    }
}
