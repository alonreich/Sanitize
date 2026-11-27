using System.Text;
using System.Text.RegularExpressions;

namespace Sanitization.Core;

public enum TextEncodingKind { Binary, Utf8, Utf8Bom, Utf16Le, Utf16Be, Latin1, Utf16LeNoBom }

public static class TextCodec
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    private static readonly HashSet<string> BinaryExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".pdb", ".so", ".dylib", ".obj", ".o", ".lib", ".a", ".class", ".jar", ".pyc", ".pyd",
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".tif", ".tiff", ".psd", ".mp3", ".mp4", ".wav",
        ".ogg", ".flac", ".avi", ".mov", ".mkv", ".webm", ".ttf", ".otf", ".woff", ".woff2", ".eot", ".bin",
        ".msi", ".cab", ".winmd", ".nupkg", ".snupkg", ".traineddata", ".onnx", ".db", ".sqlite", ".lnk",
    };

    public static readonly HashSet<string> NotInspectableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".zip", ".7z", ".rar", ".gz", ".tgz", ".docx", ".xlsx", ".pptx", ".pdf", ".msg", ".pst", ".ost", ".vsix",
        ".nupkg", ".apk", ".aab",
    };

    public static bool IsBinaryExtension(string path) => BinaryExtensions.Contains(Path.GetExtension(path));

    public static (string? Text, TextEncodingKind Kind) Decode(byte[] data)
    {
        if (data.Length >= 2 && data[0] == 0xFF && data[1] == 0xFE) return (Encoding.Unicode.GetString(data, 2, data.Length - 2), TextEncodingKind.Utf16Le);
        if (data.Length >= 2 && data[0] == 0xFE && data[1] == 0xFF) return (Encoding.BigEndianUnicode.GetString(data, 2, data.Length - 2), TextEncodingKind.Utf16Be);
        if (Array.IndexOf(data, (byte)0, 0, Math.Min(data.Length, 8192)) >= 0)
            return LooksUtf16Le(data) ? (Encoding.Unicode.GetString(data, 0, data.Length & ~1), TextEncodingKind.Utf16LeNoBom) : (null, TextEncodingKind.Binary);
        var bom = data.Length >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF;
        try
        {
            var text = bom ? StrictUtf8.GetString(data, 3, data.Length - 3) : StrictUtf8.GetString(data);
            return (text, bom ? TextEncodingKind.Utf8Bom : TextEncodingKind.Utf8);
        }
        catch (DecoderFallbackException)
        {
            return (Encoding.Latin1.GetString(data), TextEncodingKind.Latin1);
        }
    }

    /// <summary>UTF-16 LE text without a byte-order mark (e.g. PowerShell / MSBuild logs): almost every odd byte is 0 and the even bytes are printable.</summary>
    internal static bool LooksUtf16Le(byte[] data)
    {
        if (data.Length % 2 != 0) return false;
        var n = Math.Min(data.Length, 8192);
        if (n < 16) return false;
        int zeros = 0, printable = 0;
        for (var i = 0; i < n; i += 2)
        {
            if (data[i + 1] == 0) zeros++;
            var b = data[i];
            if (b is 9 or 10 or 13 || b is >= 32 and < 127) printable++;
        }
        var pairs = n / 2;
        return zeros >= pairs * 0.9 && printable >= pairs * 0.85;
    }

    public static byte[] Encode(string text, TextEncodingKind kind) => kind switch
    {
        TextEncodingKind.Utf16Le => [0xFF, 0xFE, .. Encoding.Unicode.GetBytes(text)],
        TextEncodingKind.Utf16LeNoBom => Encoding.Unicode.GetBytes(text),
        TextEncodingKind.Utf16Be => [0xFE, 0xFF, .. Encoding.BigEndianUnicode.GetBytes(text)],
        TextEncodingKind.Utf8Bom => [0xEF, 0xBB, 0xBF, .. Encoding.UTF8.GetBytes(text)],
        TextEncodingKind.Latin1 => Encoding.Latin1.GetBytes(text),
        _ => Encoding.UTF8.GetBytes(text),
    };
}

public sealed class Replacer
{
    private readonly Dictionary<string, string> _map;
    private readonly Regex? _rx;

    public Replacer(IReadOnlyDictionary<string, string> map)
    {
        _map = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (k, v) in map)
            if (!string.IsNullOrEmpty(k)) _map[k] = v;
        if (_map.Count == 0) return;
        var alternation = string.Join("|", _map.Keys.OrderByDescending(k => k.Length).Select(Heuristics.Bounded));
        _rx = new Regex(alternation, RegexOptions.CultureInvariant);
    }

    public bool IsEmpty => _rx is null;

    public string Text(string s) => _rx is null ? s : _rx.Replace(s, m => _map[m.Value]);

    public byte[] Data(byte[] raw)
    {
        if (_rx is null) return raw;
        var (text, kind) = TextCodec.Decode(raw);
        if (text is null) return raw;
        var replaced = Text(text);
        return ReferenceEquals(replaced, text) || replaced == text ? raw : TextCodec.Encode(replaced, kind);
    }
}
