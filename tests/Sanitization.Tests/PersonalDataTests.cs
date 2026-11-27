using Sanitization.Core;
using Xunit;

namespace Sanitization.Tests;

public class PersonalDataTests
{
    private static RuleSet Rules() => new(Fakes.Id, [], []);
    private static List<Hit> Scan(string text, string path = "src/app.txt") => Rules().ScanText(text, path);

    private static string WithLuhn(string body)
    {
        for (var d = 0; d <= 9; d++)
            if (PersonalData.Luhn(body + d)) return body + d;
        throw new InvalidOperationException();
    }

    private static string Group4(string s) => string.Join(" ", Enumerable.Range(0, (s.Length + 3) / 4).Select(i => s.Substring(i * 4, Math.Min(4, s.Length - i * 4))));

    [Fact]
    public void Card_number_with_valid_checksum_is_critical_and_test_cards_are_ignored()
    {
        var card = Group4(WithLuhn("453914880343646"));
        var hit = Assert.Single(Scan("card: " + card), h => h.Rule.Category == "Payment card number");
        Assert.Equal(Severity.Critical, hit.Severity);
        Assert.DoesNotContain(Scan("card: 4111 1111 1111 1111"), h => h.Rule.Category == "Payment card number");
        var bad = card[..^1] + (char)('0' + (card[^1] - '0' + 1) % 10);
        Assert.DoesNotContain(Scan("card: " + bad), h => h.Rule.Category == "Payment card number");
    }

    [Fact]
    public void Bare_digit_runs_need_a_card_word()
    {
        var digits = WithLuhn("453914880343646");
        Assert.DoesNotContain(Scan("order id " + digits), h => h.Rule.Category == "Payment card number");
        Assert.Contains(Scan("visa " + digits), h => h.Rule.Category == "Payment card number");
    }

    [Fact]
    public void Iban_is_validated_by_mod_97()
    {
        const string bban = "500105175407324931";
        var numeric = string.Concat((bban + "DE00").Select(c => char.IsDigit(c) ? c.ToString() : (c - 'A' + 10).ToString()));
        var check = 98 - (int)(System.Numerics.BigInteger.Parse(numeric) % 97);
        var iban = "DE" + check.ToString("00") + bban;
        Assert.Contains(Scan("pay to " + iban), h => h.Rule.Category == "Bank account (IBAN)");
        Assert.DoesNotContain(Scan("pay to DE" + ((check + 1) % 97).ToString("00") + bban), h => h.Rule.Category == "Bank account (IBAN)");
    }

    [Fact]
    public void Phone_numbers_are_found_and_fictional_ones_ignored()
    {
        var phone = "+972-5" + "4-731-9" + "862";
        Assert.Contains(Scan("call " + phone), h => h.Rule.Category == "Phone number");
        Assert.Contains(Scan("mobile: 05" + "4-731-9862"), h => h.Rule.Category == "Phone number");
        Assert.DoesNotContain(Scan("call +1-555-0100"), h => h.Rule.Category == "Phone number");
        Assert.DoesNotContain(Scan("released 2026-11-27"), h => h.Rule.Category == "Phone number");
    }

    [Fact]
    public void Mac_addresses_are_found_but_placeholders_are_not()
    {
        var mac = string.Join(":", "3C", "52", "82", "9A", "E1", "47");
        var hit = Assert.Single(Scan("wifi " + mac), h => h.Rule.Category == "MAC address");
        Assert.Equal("00:00:5E:00:53:01", hit.Replacement);
        Assert.DoesNotContain(Scan("mac 00:11:22:33:44:55"), h => h.Rule.Category == "MAC address");
        Assert.DoesNotContain(Scan("ff:ff:ff:ff:ff:ff"), h => h.Rule.Category == "MAC address");
    }

    [Fact]
    public void Own_mac_is_high()
    {
        var id = new MachineIdentity { UserName = "zqtestuser", MachineName = "ZQ-WORKSTATION", MacAddresses = ["00:00:5E:00:53:02"] };
        var hits = new RuleSet(id, [], []).ScanText("adapter 00-00-5e-00-53-02", "a.txt");
        Assert.Equal(Severity.High, Assert.Single(hits).Severity);
    }

    [Fact]
    public void Ids_passports_ssn_dob_imei_and_gps_need_labels_or_checksums()
    {
        Assert.Contains(Scan("Passport No: " + "X" + "8827" + "3641"), h => h.Rule.Category == "ID / passport / licence number");
        var ssn = "52" + "4-63-71" + "89";
        Assert.Equal(Severity.High, Assert.Single(Scan("SSN " + ssn), h => h.Rule.Category == "Social Security number").Severity);
        Assert.DoesNotContain(Scan("SSN 123-45-6789"), h => h.Rule.Category == "Social Security number");
        Assert.Contains(Scan("DOB: 1970-01-01"), h => h.Rule.Category == "Date of birth");
        Assert.Contains(Scan("IMEI " + WithLuhn("35209900176148")), h => h.Rule.Category == "Device ID (IMEI)");
        Assert.Contains(Scan("location: 32.07" + "5312, 34.78" + "1768"), h => h.Rule.Category == "GPS location");
        Assert.DoesNotContain(Scan("scale = 0.000000, 0.000000"), h => h.Rule.Category == "GPS location");
    }

    [Theory]
    [InlineData("var json = JsonSerializer.SerializeToUtf8Bytes(settings, ctx);")]
    [InlineData("a=+2147483647,b=+67108864")]
    [InlineData("const t = 0769230769;")]
    public void Code_is_not_personal_data(string code) =>
        Assert.DoesNotContain(Scan(code), h => h.Rule.Category is "Device serial / hardware ID" or "Phone number");

    [Fact]
    public void Israeli_id_check_digit()
    {
        Assert.True(PersonalData.IsraeliIdValid("000000018"));
        Assert.False(PersonalData.IsraeliIdValid("000000019"));
    }

    [Fact]
    public void Personal_data_in_tests_is_low()
    {
        var phone = "+972-5" + "4-731-9" + "862";
        Assert.Equal(Severity.Low, Assert.Single(Scan("call " + phone, "tests/ContactTests.cs"), h => h.Rule.Category == "Phone number").Severity);
    }

    internal static byte[] JpegWithGps(bool gps = true)
    {
        var tiff = new List<byte>();
        void U16(int v) { tiff.Add((byte)v); tiff.Add((byte)(v >> 8)); }
        void U32(uint v) { for (var i = 0; i < 4; i++) tiff.Add((byte)(v >> (8 * i))); }
        tiff.AddRange("II"u8.ToArray()); U16(42); U32(8);
        U16(1); U16(0x8825); U16(4); U32(1); U32(26); U32(0);
        U16(1); U16(0x0002); U16(5); U32(3); U32(44); U32(0);
        foreach (var (n, d) in new[] { (gps ? 32u : 0u, 1u), (gps ? 4u : 0u, 1u), (gps ? 3000u : 0u, 100u) }) { U32(n); U32(d); }
        var exif = "Exif\0\0"u8.ToArray().Concat(tiff).ToArray();
        var len = exif.Length + 2;
        return new byte[] { 0xFF, 0xD8, 0xFF, 0xE1, (byte)(len >> 8), (byte)len }.Concat(exif)
            .Concat(new byte[] { 0xFF, 0xDB, 0x00, 0x04, 0x01, 0x02, 0xFF, 0xD9 }).ToArray();
    }

    [Fact]
    public void Gps_in_jpeg_is_detected_and_stripped()
    {
        var jpeg = JpegWithGps();
        Assert.True(PhotoLocation.HasGps(jpeg));
        Assert.False(PhotoLocation.HasGps(JpegWithGps(gps: false)));
        var stripped = PhotoLocation.StripExif(jpeg);
        Assert.False(PhotoLocation.HasGps(stripped));
        Assert.Equal(new byte[] { 0xFF, 0xD8, 0xFF, 0xDB, 0x00, 0x04, 0x01, 0x02, 0xFF, 0xD9 }, stripped);
    }

    [Fact]
    public async Task Photo_gps_is_fixed_in_files_and_git_history()
    {
        using var repo = new TestRepo();
        repo.WriteBytes("docs/shot.jpg", JpegWithGps());
        repo.Commit("add photo");
        var result = await Scanner.ScanAsync(repo.Info, Fakes.Id, [], [], null, CancellationToken.None);
        var f = Assert.Single(result.Findings, x => x.PhotoGps);
        Assert.True(f.Actions.HasFlag(FixActions.StripPhotoGps) && f.Actions.HasFlag(FixActions.StripPhotoGpsInHistory));
        var outcome = await Fixer.ApplyAsync(result.Project, [f], true, new UndoBatch(), null, CancellationToken.None);
        Assert.True(outcome.HistoryRewritten);
        Assert.False(PhotoLocation.HasGps(File.ReadAllBytes(Path.Combine(repo.Path, "docs", "shot.jpg"))));
        var after = await Scanner.ScanAsync(repo.Info, Fakes.Id, [], [], null, CancellationToken.None);
        Assert.DoesNotContain(after.Findings, x => x.PhotoGps);
    }
}
