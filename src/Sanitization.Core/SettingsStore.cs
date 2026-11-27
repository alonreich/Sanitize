using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Sanitization.Core;

public sealed class AppSettings
{
    public string? ScanRoot { get; set; }
    public List<PrivateTerm> PrivateTerms { get; set; } = [];
    public Dictionary<string, List<string>> Ignored { get; set; } = [];
    public Dictionary<string, string> Placeholders { get; set; } = [];
    public List<string> OrgTerms { get; set; } = [];
    public double WindowWidth { get; set; }
    public double WindowHeight { get; set; }
    public bool WindowMaximized { get; set; } = true;

    public List<string> IgnoredFor(string projectPath) =>
        Ignored.TryGetValue(projectPath.ToLowerInvariant(), out var l) ? l : [];

    public void Ignore(string projectPath, string value)
    {
        var key = projectPath.ToLowerInvariant();
        if (!Ignored.TryGetValue(key, out var l)) Ignored[key] = l = [];
        if (!l.Contains(value, StringComparer.OrdinalIgnoreCase)) l.Add(value);
    }

    public void Unignore(string projectPath, string value)
    {
        var key = projectPath.ToLowerInvariant();
        if (Ignored.TryGetValue(key, out var l))
        {
            l.RemoveAll(v => string.Equals(v, value, StringComparison.OrdinalIgnoreCase));
            if (l.Count == 0) Ignored.Remove(key);
        }
    }
}

[JsonSourceGenerationOptions(WriteIndented = false)]
[JsonSerializable(typeof(AppSettings))]
internal sealed partial class SettingsJsonContext : JsonSerializerContext;

public static class SettingsStore
{
    private static readonly byte[] Entropy = "Sanitization.Settings.v1"u8.ToArray();

    public static string Directory_ { get; set; } =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Sanitization");

    public static string FilePath => Path.Combine(Directory_, "settings.dat");

    public static AppSettings Load()
    {
        try
        {
            if (!File.Exists(FilePath)) return new AppSettings();
            var plain = ProtectedData.Unprotect(File.ReadAllBytes(FilePath), Entropy, DataProtectionScope.CurrentUser);
            try
            {
                return JsonSerializer.Deserialize(plain, SettingsJsonContext.Default.AppSettings) ?? new AppSettings();
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plain);
            }
        }
        catch
        {
            return new AppSettings();
        }
    }

    public static void Save(AppSettings s)
    {
        Directory.CreateDirectory(Directory_);
        var plain = JsonSerializer.SerializeToUtf8Bytes(s, SettingsJsonContext.Default.AppSettings);
        try
        {
            var cipher = ProtectedData.Protect(plain, Entropy, DataProtectionScope.CurrentUser);
            var tmp = FilePath + ".tmp";
            File.WriteAllBytes(tmp, cipher);
            File.Move(tmp, FilePath, true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    public static bool IsInsideSettings(string path) =>
        Path.GetFullPath(path).StartsWith(Path.GetFullPath(Directory_), StringComparison.OrdinalIgnoreCase);

    internal static string Describe(AppSettings s) => Encoding.UTF8.GetString(JsonSerializer.SerializeToUtf8Bytes(s, SettingsJsonContext.Default.AppSettings));
}
