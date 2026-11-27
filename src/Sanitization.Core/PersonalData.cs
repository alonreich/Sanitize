using System.Globalization;
using System.Numerics;
using System.Text.RegularExpressions;

namespace Sanitization.Core;

internal static partial class PersonalData
{
    [GeneratedRegex(@"(?<![0-9A-Fa-f:.-])[0-9A-Fa-f]{2}([:-])(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:.-])|(?<![0-9A-Fa-f.])[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}(?![0-9A-Fa-f.])")]
    private static partial Regex Mac();

    [GeneratedRegex(@"(?<![\d.-])(?:\d{4}([ -])\d{4}\1\d{4}\1\d{1,7}|\d{4}([ -])\d{6}\2\d{4,5}|\d{13,19})(?![\d.-])")]
    private static partial Regex Card();

    [GeneratedRegex(@"(?<![A-Za-z0-9])[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?(?![A-Za-z0-9])")]
    private static partial Regex Iban();

    [GeneratedRegex(@"(?<![\d-])(\d{3})-(\d{2})-(\d{4})(?![\d-])")]
    private static partial Regex Ssn();

    [GeneratedRegex(@"(?i)(?<![A-Za-z])(?:passport|דרכון|national[ _-]?id|id[ _-]?(?:no|num|number)|identity[ _-]?(?:no|number|card)|teudat[ _-]?zehut|ת[""']?ז|תעודת[ _-]?זהות|driver'?s?[ _-]?licen[cs]e|licen[cs]e[ _-]?(?:no|number)|social[ _-]?security|tax[ _-]?id|ssn)(?:[ _-]?(?:no|number|num|#))?(?![A-Za-z])[""']?\s*[:=#]?\s*[""']?([A-Z0-9][A-Z0-9-]{4,16})")]
    private static partial Regex LabeledId();

    [GeneratedRegex(@"(?<![\w+])\+\d{1,3}(?=[\d ().-]*[ .()-])[ .-]?(?:\(\d{1,4}\)[ .-]?)?\d{1,4}(?:[ .-]?\d{2,4}){1,4}(?![\w])")]
    private static partial Regex IntlPhone();

    [GeneratedRegex(@"(?<![\d-])05\d[ -]?\d{3}[ -]?\d{4}(?![\d-])|(?<![\w(])\(\d{3}\)[ ]?\d{3}-\d{4}(?![\d-])")]
    private static partial Regex LocalPhone();

    [GeneratedRegex(@"(?i)(?<![A-Za-z])(?:phone|tel|telephone|mobile|cell|cellphone|fax|whatsapp|טלפון|נייד|פלאפון)(?![A-Za-z])[""']?\s*[:=]?\s*[""']?(\+?\d[\d ()./-]{6,18}\d)")]
    private static partial Regex LabeledPhone();

    [GeneratedRegex(@"(?i)(?<![A-Za-z])(?:dob|date[ _-]?of[ _-]?birth|birth[ _-]?date|birthday|born(?:[ _-]on)?|תאריך[ _-]?לידה)(?![A-Za-z])[""']?\s*[:=]?\s*[""']?(\d{1,4}[./-]\d{1,2}[./-]\d{1,4})")]
    private static partial Regex Dob();

    [GeneratedRegex(@"(?<![\d.])(-?\d{1,2}\.\d{5,})\s*,\s*(-?\d{1,3}\.\d{5,})(?![\d.])")]
    private static partial Regex Coordinates();

    [GeneratedRegex(@"(?i)lat|lng|lon|latitude|longitude|gps|coord|location|maps|geo")]
    private static partial Regex GeoWord();

    [GeneratedRegex(@"(?i)(?<![A-Za-z])(?:imei|meid)(?![A-Za-z])[""']?\s*[:=#]?\s*[""']?(\d{15})(?!\d)")]
    private static partial Regex Imei();

    [GeneratedRegex(@"(?i)(?<![A-Za-z])(?:machine[ _-]?guid|machine[ _-]?id|hardware[ _-]?id|hwid|device[ _-]?id|serial[ _-]?(?:no|number|num)?|bios[ _-]?serial)(?![A-Za-z])[""']?\s*[:=#]?\s*[""']?([A-Za-z0-9][A-Za-z0-9-]{7,40})")]
    private static partial Regex DeviceId();

    [GeneratedRegex(@"(?i)card|visa|master|amex|credit|debit|payment|cc[_-]?num|pan\b|כרטיס")]
    private static partial Regex CardWord();

    [GeneratedRegex(@"(?i)ssn|social|security|tax|employee|ss#")]
    private static partial Regex SsnWord();

    private static readonly HashSet<string> TestCards =
    [
        "4111111111111111", "4242424242424242", "4012888888881881", "4000056655665556", "4000000000000002", "4000000000000077",
        "4000000000000093", "5555555555554444", "5105105105105100", "5200828282828210", "2223003122003222", "378282246310005",
        "371449635398431", "378734493671000", "6011111111111117", "6011000990139424", "3530111333300000", "3566002020360505",
        "30569309025904", "38520000023237", "6200000000000005", "4917610000000000", "6304000000000000",
    ];

    private static readonly HashSet<string> TestIbans =
    [
        "GB82WEST12345698765432", "GB33BUKB20201555555555", "DE89370400440532013000", "FR1420041010050500013M02606",
        "IL620108000000099999999", "NL91ABNA0417164300", "ES9121000418450200051332", "IT60X0542811101000000123456",
        "CH9300762011623852957", "BE68539007547034", "AT611904300234573201", "SE4550000000058398257466", "NO9386011117947",
        "DK5000400440116243", "FI2112345600000785", "PL61109010140000071219812874", "SA0380000000608010167519", "AE070331234567890123456",
    ];

    private static readonly HashSet<string> TestSsns = ["123-45-6789", "078-05-1120", "219-09-9999", "457-55-5462", "111-22-3333", "000-00-0000"];

    private static readonly HashSet<string> PlaceholderMacs = new(StringComparer.OrdinalIgnoreCase)
    {
        "000000000000", "FFFFFFFFFFFF", "001122334455", "AABBCCDDEEFF", "0123456789AB", "112233445566", "DEADBEEFCAFE",
        "AA0000000000", "010203040506", "123456789ABC", "00005E005301",
    };

    public static void AddRules(List<Rule> rules)
    {
        rules.Add(new Rule { Category = "Payment card number", Regex = Card(), Severity = Severity.Critical, Generic = true,
            Why = "A real-looking credit / debit card number (passes the card checksum).", Replace = _ => "XXXX-XXXX-XXXX-XXXX", Validate = ValidateCard });
        rules.Add(new Rule { Category = "Bank account (IBAN)", Regex = Iban(), Severity = Severity.High, Generic = true,
            Why = "A valid international bank account number.", Replace = _ => "IBAN-REDACTED", Validate = ValidateIban });
        rules.Add(new Rule { Category = "Social Security number", Regex = Ssn(), Severity = Severity.High, Generic = true,
            Why = "A US Social Security number identifies a person for life.", Replace = _ => "000-00-0000", Validate = ValidateSsn });
        rules.Add(new Rule { Category = "ID / passport / licence number", Regex = LabeledId(), Severity = Severity.High, Generic = true, ValueGroup = 1,
            Why = "A government ID, passport, licence or tax number identifies a person.", Replace = _ => "REDACTED_ID", Validate = ValidateLabeledId });
        rules.Add(new Rule { Category = "Phone number", Regex = IntlPhone(), Severity = Severity.Medium, Generic = true,
            Why = "Someone's phone number. Check whether it is real.", Replace = _ => "+1-555-0100", PlaceholderKind = "phone", Validate = ValidatePhone });
        rules.Add(new Rule { Category = "Phone number", Regex = LocalPhone(), Severity = Severity.Medium, Generic = true,
            Why = "Someone's phone number. Check whether it is real.", Replace = _ => "+1-555-0100", PlaceholderKind = "phone", Validate = ValidatePhone });
        rules.Add(new Rule { Category = "Phone number", Regex = LabeledPhone(), Severity = Severity.Medium, Generic = true, ValueGroup = 1,
            Why = "Someone's phone number. Check whether it is real.", Replace = _ => "+1-555-0100", PlaceholderKind = "phone", Validate = (m, t, p) => ValidatePhoneDigits(m.Groups[1].Value) });
        rules.Add(new Rule { Category = "Date of birth", Regex = Dob(), Severity = Severity.Medium, Generic = true, ValueGroup = 1,
            Why = "A birth date helps identify a person (and answer security questions).", Replace = _ => "1970-01-01",
            Validate = (m, _, _) => m.Groups[1].Value is "1970-01-01" or "01/01/1970" or "1/1/1970" or "01.01.1970" ? Verdict.Drop : Verdict.Keep });
        rules.Add(new Rule { Category = "GPS location", Regex = Coordinates(), Severity = Severity.Medium, Generic = true,
            Why = "Precise coordinates can point to a home or workplace.", Replace = _ => "0.000000, 0.000000", Validate = ValidateCoordinates });
        rules.Add(new Rule { Category = "Device ID (IMEI)", Regex = Imei(), Severity = Severity.High, Generic = true, ValueGroup = 1,
            Why = "An IMEI identifies one specific phone.", Replace = _ => "000000000000000",
            Validate = (m, _, _) => Luhn(m.Groups[1].Value) && !Heuristics.LooksPlaceholder(m.Groups[1].Value) ? Verdict.Keep : Verdict.Drop });
        rules.Add(new Rule { Category = "Device serial / hardware ID", Regex = DeviceId(), Severity = Severity.Medium, Generic = true, ValueGroup = 1,
            Why = "A serial number or hardware ID ties the data to one specific machine.", Replace = _ => "REDACTED_DEVICE_ID", Validate = ValidateDeviceId });
        rules.Add(new Rule { Category = "MAC address", Regex = Mac(), Severity = Severity.Medium, Generic = true,
            Why = "Identifies one network card (and can locate it via Wi-Fi databases).", Replace = ReplaceMac, Validate = ValidateMac, PlaceholderKind = "mac" });
    }

    internal static string ReplaceMac(Match m)
    {
        var v = m.Value;
        if (v.Length == 14 && v[4] == '.') return "0000.5e00.5301";
        var sep = v.Length > 2 && !char.IsAsciiHexDigit(v[2]) ? v[2].ToString() : ":";
        return string.Join(sep, "00", "00", "5E", "00", "53", "01");
    }

    private static string Hex(string v) => string.Concat(v.Where(char.IsAsciiHexDigit)).ToUpperInvariant();

    private static Verdict ValidateMac(Match m, string text, string path)
    {
        var hex = Hex(m.Value);
        if (PlaceholderMacs.Contains(hex) || hex.Distinct().Count() <= 2 || Heuristics.AscendingRun(hex, 6)) return Verdict.Drop;
        if (hex.StartsWith("00005E0053", StringComparison.Ordinal)) return Verdict.Drop;
        if (hex.All(char.IsAsciiDigit)) return Verdict.Low;
        var first = Convert.ToInt32(hex[..2], 16);
        return (first & 0x03) != 0 ? Verdict.Low : Verdict.Keep;
    }

    internal static bool Luhn(string digits)
    {
        var sum = 0;
        var dbl = false;
        for (var i = digits.Length - 1; i >= 0; i--)
        {
            var d = digits[i] - '0';
            if (dbl) { d *= 2; if (d > 9) d -= 9; }
            sum += d;
            dbl = !dbl;
        }
        return sum % 10 == 0;
    }

    private static bool KnownCardPrefix(string d)
    {
        int P(int n) => int.Parse(d[..n], CultureInfo.InvariantCulture);
        return d[0] == '4' && d.Length is 13 or 16 or 19
            || P(2) is >= 51 and <= 55 && d.Length == 16 || P(4) is >= 2221 and <= 2720 && d.Length == 16
            || P(2) is 34 or 37 && d.Length == 15
            || (d.StartsWith("6011", StringComparison.Ordinal) || P(2) == 65 || P(3) is >= 644 and <= 649) && d.Length is 16 or 19
            || P(4) is >= 3528 and <= 3589 && d.Length is >= 16 and <= 19
            || (P(3) is >= 300 and <= 305 || P(2) is 36 or 38) && d.Length is 14 or 16
            || P(2) == 62 && d.Length is >= 16 and <= 19;
    }

    private static Verdict ValidateCard(Match m, string text, string path)
    {
        var d = string.Concat(m.Value.Where(char.IsAsciiDigit));
        if (d.Length is < 13 or > 19 || TestCards.Contains(d) || !KnownCardPrefix(d) || !Luhn(d)) return Verdict.Drop;
        if (d.Distinct().Count() <= 3 || Heuristics.AscendingRun(d, 6)) return Verdict.Drop;
        if (m.Value.All(char.IsAsciiDigit))
        {
            var start = Math.Max(0, m.Index - 40);
            if (!CardWord().IsMatch(text.AsSpan(start, Math.Min(text.Length, m.Index + m.Length + 20) - start).ToString())) return Verdict.Drop;
        }
        return Verdict.Keep;
    }

    private static Verdict ValidateIban(Match m, string text, string path)
    {
        var s = m.Value.Replace(" ", "");
        if (s.Length is < 15 or > 34 || TestIbans.Contains(s)) return Verdict.Drop;
        var rearranged = s[4..] + s[..4];
        var numeric = string.Concat(rearranged.Select(c => char.IsAsciiDigit(c) ? c.ToString() : (c - 'A' + 10).ToString(CultureInfo.InvariantCulture)));
        if (!BigInteger.TryParse(numeric, NumberStyles.None, CultureInfo.InvariantCulture, out var n) || n % 97 != 1) return Verdict.Drop;
        var digits = string.Concat(s[4..].Where(char.IsAsciiDigit));
        return digits.Distinct().Count() <= 2 || digits.Contains("0000000000", StringComparison.Ordinal) && digits.Contains("9999", StringComparison.Ordinal) ? Verdict.Low : Verdict.Keep;
    }

    private static Verdict ValidateSsn(Match m, string text, string path)
    {
        if (TestSsns.Contains(m.Value)) return Verdict.Drop;
        var area = int.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture);
        if (area is 0 or 666 || area >= 900 || m.Groups[2].Value == "00" || m.Groups[3].Value == "0000") return Verdict.Drop;
        var start = Math.Max(0, m.Index - 40);
        return SsnWord().IsMatch(text.AsSpan(start, m.Index - start).ToString()) ? Verdict.Keep : Verdict.Low;
    }

    internal static bool IsraeliIdValid(string id)
    {
        if (id.Length is < 5 or > 9 || !id.All(char.IsAsciiDigit)) return false;
        id = id.PadLeft(9, '0');
        var sum = 0;
        for (var i = 0; i < 9; i++)
        {
            var d = (id[i] - '0') * (i % 2 + 1);
            sum += d > 9 ? d - 9 : d;
        }
        return sum % 10 == 0;
    }

    private static Verdict ValidateLabeledId(Match m, string text, string path)
    {
        var v = m.Groups[1].Value;
        if (!v.Any(char.IsAsciiDigit) || Heuristics.LooksPlaceholder(v) || v.All(c => c == '0' || c == '-')) return Verdict.Drop;
        var label = m.Value[..(m.Groups[1].Index - m.Index)];
        var israeli = Regex.IsMatch(label, @"(?i)teudat|ת[""']?ז|תעודת|identity|national|id[ _-]?(no|num)");
        if (israeli && v.All(char.IsAsciiDigit) && v.Length is >= 8 and <= 9) return IsraeliIdValid(v) ? Verdict.Keep : Verdict.Low;
        return v.Count(char.IsAsciiDigit) >= 4 ? Verdict.Keep : Verdict.Low;
    }

    private static Verdict ValidatePhoneDigits(string raw)
    {
        var d = string.Concat(raw.Where(char.IsAsciiDigit));
        if (d.Length is < 8 or > 15 || d.Distinct().Count() <= 2 || Heuristics.AscendingRun(d, 6)) return Verdict.Drop;
        if (ulong.TryParse(d, out var n) && n > 0 && ((n & (n - 1)) == 0 || ((n + 1) & n) == 0)) return Verdict.Drop;
        if (d.StartsWith("4420794", StringComparison.Ordinal) || d.StartsWith("020794", StringComparison.Ordinal)) return Verdict.Drop;
        if (d.Contains("555", StringComparison.Ordinal) && (d.StartsWith("1555", StringComparison.Ordinal) || d.Contains("5550", StringComparison.Ordinal) || d.StartsWith("555", StringComparison.Ordinal))) return Verdict.Drop;
        if (Heuristics.LooksPlaceholder(raw) && d.Distinct().Count() < 5) return Verdict.Drop;
        return Verdict.Keep;
    }

    private static Verdict ValidatePhone(Match m, string text, string path)
    {
        var v = m.Value;
        if (Regex.IsMatch(v, @"^\+?\d{4}[-./]\d{1,2}[-./]\d{1,2}$") || v.Count(c => c == '.') >= 3 && !v.StartsWith('+')) return Verdict.Drop;
        return ValidatePhoneDigits(v);
    }

    private static Verdict ValidateCoordinates(Match m, string text, string path)
    {
        if (!double.TryParse(m.Groups[1].Value, NumberStyles.Float, CultureInfo.InvariantCulture, out var lat) ||
            !double.TryParse(m.Groups[2].Value, NumberStyles.Float, CultureInfo.InvariantCulture, out var lon)) return Verdict.Drop;
        if (Math.Abs(lat) > 90 || Math.Abs(lon) > 180 || Math.Abs(lat) < 0.01 && Math.Abs(lon) < 0.01) return Verdict.Drop;
        var start = Math.Max(0, m.Index - 60);
        var around = text.AsSpan(start, Math.Min(text.Length, m.Index + m.Length + 30) - start).ToString();
        return GeoWord().IsMatch(around) ? Verdict.Keep : Verdict.Drop;
    }

    private static Verdict ValidateDeviceId(Match m, string text, string path)
    {
        var v = m.Groups[1].Value;
        if (!v.Any(char.IsAsciiDigit) || Heuristics.LooksPlaceholder(v) || v.All(c => c is '0' or '-')) return Verdict.Drop;
        if (Patterns.LettersOnly().IsMatch(v) || v.Equals("number", StringComparison.OrdinalIgnoreCase)) return Verdict.Drop;
        return v.Count(char.IsAsciiDigit) >= 3 && v.Distinct().Count() >= 6 ? Verdict.Keep : Verdict.Low;
    }
}

public static class PhotoLocation
{
    public static readonly HashSet<string> Extensions = new(StringComparer.OrdinalIgnoreCase) { ".jpg", ".jpeg", ".jpe", ".jfif" };

    public static bool IsJpeg(byte[] d) => d.Length > 4 && d[0] == 0xFF && d[1] == 0xD8;

    public static bool HasGps(byte[] d)
    {
        try
        {
            foreach (var (start, length) in ExifSegments(d))
            {
                var tiff = start + 10;
                if (tiff + 8 > d.Length) continue;
                var le = d[tiff] == 'I';
                int U16(int o) => le ? d[o] | d[o + 1] << 8 : d[o] << 8 | d[o + 1];
                uint U32(int o) => le ? (uint)(d[o] | d[o + 1] << 8 | d[o + 2] << 16 | d[o + 3] << 24) : (uint)(d[o] << 24 | d[o + 1] << 16 | d[o + 2] << 8 | d[o + 3]);
                var end = start + 2 + length;
                var ifd0 = tiff + (int)U32(tiff + 4);
                if (ifd0 + 2 > end) continue;
                var gpsIfd = -1;
                for (int i = 0, n = U16(ifd0); i < n && ifd0 + 2 + i * 12 + 12 <= end; i++)
                {
                    var e = ifd0 + 2 + i * 12;
                    if (U16(e) == 0x8825) gpsIfd = tiff + (int)U32(e + 8);
                }
                if (gpsIfd < 0 || gpsIfd + 2 > end) continue;
                for (int i = 0, n = U16(gpsIfd); i < n && gpsIfd + 2 + i * 12 + 12 <= end; i++)
                {
                    var e = gpsIfd + 2 + i * 12;
                    var tag = U16(e);
                    if (tag is not (2 or 4)) continue;
                    var off = tiff + (int)U32(e + 8);
                    for (var k = 0; k < 3 && off + k * 8 + 8 <= end; k++)
                        if (U32(off + k * 8) != 0) return true;
                }
            }
        }
        catch { }
        return false;
    }

    private static IEnumerable<(int Start, int Length)> ExifSegments(byte[] d)
    {
        if (!IsJpeg(d)) yield break;
        var p = 2;
        while (p + 4 <= d.Length && d[p] == 0xFF)
        {
            var marker = d[p + 1];
            if (marker is 0xD9 or 0xDA) yield break;
            var len = d[p + 2] << 8 | d[p + 3];
            if (len < 2 || p + 2 + len > d.Length) yield break;
            if (marker == 0xE1 && len > 8 && d[p + 4] == 'E' && d[p + 5] == 'x' && d[p + 6] == 'i' && d[p + 7] == 'f') yield return (p, len);
            p += 2 + len;
        }
    }

    public static byte[] StripExif(byte[] d)
    {
        var segments = ExifSegments(d).ToList();
        if (segments.Count == 0) return d;
        var ms = new MemoryStream(d.Length);
        var pos = 0;
        foreach (var (start, length) in segments)
        {
            ms.Write(d, pos, start - pos);
            pos = start + 2 + length;
        }
        ms.Write(d, pos, d.Length - pos);
        return ms.ToArray();
    }
}
