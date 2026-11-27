using System.IO.Compression;
using System.Text;
using Sanitization.Core;
using Xunit;

namespace Sanitization.Tests;

public class ImprovementTests
{
    private static async Task<ProjectScanResult> Scan(TestRepo repo, ScanContext? ctx = null) =>
        await Scanner.ScanAsync(repo.Info, Fakes.Id, [], [], null, CancellationToken.None, ctx);

    // Fictional values that the scanner must still detect. They are split so the
    // scanner does not flag this test file itself.
    private const string Ip1 = "198." + "20.47.61";
    private const string Ip2 = "198." + "20.47.62";
    private const string Mail1 = "zq.one@" + "fictmail.net";
    private const string Mail2 = "zq.two@" + "fictmail.net";
    private const string OfficeMail = "zq.office@" + "fictmail.net";
    private const string OrgMail = "dana@" + "acmewidgets.co.il";
    private const string Tenant = "acmewidgets" + "prod.service-now.com";
    private const string Okta = "initrode7" + ".okta.com";
    private const string RecordId = "4b7e19c2a8f05d36" + "e1c9a7b2d4f80e15";
    private const string Customer = "customer-" + "73914826";
    private const string Phone = "05" + "2-9183746";

    [Fact]
    public async Task Value_found_once_is_reported_everywhere_it_appears()
    {
        using var repo = new TestRepo();
        repo.Write("deploy/hosts.txt", "server " + Ip1);
        repo.Write("tests/App.Tests/HostTests.cs", $"Assert.Equal(\"{Ip1}\", host);");
        repo.Write("docs/notes.md", "release 1.0 build " + Ip1);
        repo.Commit("add");

        var result = await Scan(repo);
        var hits = result.Findings.Where(f => f.Value == Ip1).ToList();
        Assert.Equal(["deploy/hosts.txt", "docs/notes.md", "tests/App.Tests/HostTests.cs"], hits.Select(f => f.RelativePath).Order().ToList());
        Assert.All(hits, f => Assert.Equal(Severity.Medium, f.Severity));
        Assert.Single(hits.Select(f => f.Replacement).Distinct());
    }

    [Fact]
    public async Task Different_values_get_different_placeholders_and_the_map_is_remembered()
    {
        using var repo = new TestRepo();
        repo.Write("a.txt", $"primary {Ip1}\nbackup {Ip2}\nmail {Mail1} and {Mail2}");
        repo.Commit("add");
        var settings = new AppSettings();

        var first = await Scan(repo, new ScanContext(settings));
        var r1 = first.Findings.Single(f => f.Value == Ip1).Replacement;
        var r2 = first.Findings.Single(f => f.Value == Ip2).Replacement;
        Assert.NotEqual(r1, r2);
        Assert.StartsWith("203.0.113.", r1);
        Assert.NotEqual(first.Findings.Single(f => f.Value == Mail1).Replacement, first.Findings.Single(f => f.Value == Mail2).Replacement);
        Assert.DoesNotContain(settings.Placeholders.Keys.Concat(settings.Placeholders.Values), k => k.Contains(Ip1, StringComparison.Ordinal));

        var again = await Scan(repo, new ScanContext(settings));
        Assert.Equal(r1, again.Findings.Single(f => f.Value == Ip1).Replacement);
        Assert.Equal(r2, again.Findings.Single(f => f.Value == Ip2).Replacement);
    }

    [Fact]
    public async Task Organisation_is_learned_from_email_domain_and_tenants_and_ids_are_found()
    {
        using var repo = new TestRepo();
        repo.Write("config.json", $$"""
            { "reportTo": "{{OrgMail}}",
              "instance": "https://{{Tenant}}/now/nav/ui/list.do%3Fsysparm_query%3Dsys_domain%253D{{RecordId}}",
              "group": "Acmewidgets Developers", "sso": "https://{{Okta}}/app" }
            """);
        repo.Write("audit/summary.txt", "Tenant: " + Customer);
        repo.Commit("add");

        var settings = new AppSettings();
        var result = await Scan(repo, new ScanContext(settings));
        Assert.Contains(settings.OrgTerms, t => t.StartsWith("acmewidgets|", StringComparison.Ordinal));
        var org = Assert.Single(result.Findings, f => f.Value == "Acmewidgets");
        Assert.Equal("Contoso", org.Replacement);
        Assert.Contains(result.Findings, f => f.Value.Contains(Tenant, StringComparison.Ordinal) && f.Replacement!.Contains("contoso", StringComparison.Ordinal));
        var okta = result.Findings.Single(f => f.Value == Okta).Replacement!;
        Assert.Matches(@"^(contoso|fabrikam)\.okta\.com$", okta);
        Assert.Contains(result.Findings, f => f.Category == "Record ID in a company URL" && f.Value == RecordId);
        Assert.Contains(result.Findings, f => f.Category == "Cloud tenant / customer ID" && f.Value == Customer);
    }

    [Fact]
    public async Task Office_documents_are_read_and_reported_but_not_auto_fixed()
    {
        using var repo = new TestRepo();
        repo.WriteBytes("report.xlsx", Xlsx("Owner: " + OfficeMail, "Dana Levi"));
        repo.Commit("add");

        var result = await Scan(repo);
        var mail = Assert.Single(result.Findings, f => f.Value == OfficeMail);
        Assert.True(mail.InsideDocument);
        Assert.False(mail.CanFix);
        Assert.Contains("Office document", mail.NoFixReason);
        Assert.Contains(result.Findings, f => f.Category == "Document author / company" && f.Value == "Dana Levi");
    }

    [Fact]
    public async Task Real_author_name_is_flagged_and_rewritten()
    {
        using var repo = new TestRepo();
        repo.Git("config", "user.name", "Dana Levi");
        repo.Write("a.txt", "hello");
        repo.Commit("first");

        var result = await Scan(repo);
        var name = Assert.Single(result.Findings, f => f.Kind == FindingKind.CommitIdentity && f.Value == "Dana Levi");
        Assert.Equal("Dev User", name.Replacement);
        Assert.DoesNotContain(result.Findings, f => f.Value == "Tester");
        var outcome = await Fixer.ApplyAsync(result.Project, [name], true, new UndoBatch(), null, CancellationToken.None);
        Assert.True(outcome.HistoryRewritten);
        var authors = repo.Git("log", "--all", "--format=%an|%cn");
        Assert.DoesNotContain("Dana Levi", authors);
        Assert.Contains("Dev User", authors);
    }

    [Theory]
    [InlineData("<UnitTestResult executionId=\"ada931ae-9d04-4860-a054-0554680d0b29\" />")]
    [InlineData("SkiaSharp 3.119.4, Xamarin.AndroidX.Biometric 1.1.0.33.")]
    [InlineData("hash 3f9a0554680123bc4e5d6f7a8b9c0d1e")]
    public void Ids_and_package_versions_are_not_phones_or_ips(string text) =>
        Assert.DoesNotContain(new RuleSet(Fakes.Id, [], []).ScanText(text, "notes.txt"), h => h.Rule.Category is "Phone number" or "Public IP address");

    [Fact]
    public void Placeholder_tenants_and_fictional_uk_numbers_are_ignored()
    {
        var hits = new RuleSet(Fakes.Id, [], []).ScanText("https://your-instance.service-now.com and something.service-now.com, call +44 20 7946 0123", "docs/setup.md");
        Assert.DoesNotContain(hits, h => h.Rule.Category is "Company cloud tenant" or "Phone number");
    }

    [Fact]
    public void Real_phone_and_ip_outside_ids_are_still_found()
    {
        var hits = new RuleSet(Fakes.Id, [], []).ScanText("call " + Phone + " or reach " + Ip1, "notes.txt");
        Assert.Contains(hits, h => h.Rule.Category == "Phone number");
        Assert.Contains(hits, h => h.Rule.Category == "Public IP address");
    }

    private static byte[] Xlsx(string cellText, string author)
    {
        var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, true))
        {
            void Add(string name, string xml)
            {
                using var w = new StreamWriter(zip.CreateEntry(name).Open(), new UTF8Encoding(false));
                w.Write(xml);
            }
            Add("[Content_Types].xml", "<Types/>");
            Add("xl/sharedStrings.xml", $"<sst><si><t>{cellText}</t></si></sst>");
            Add("docProps/core.xml", $"<cp:coreProperties><dc:creator>{author}</dc:creator><cp:lastModifiedBy>openpyxl</cp:lastModifiedBy></cp:coreProperties>");
        }
        return ms.ToArray();
    }
}
