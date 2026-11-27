using Avalonia;

namespace Sanitization.App;

internal static class Program
{
    /// <summary>From <c>--scan "folder"</c>: start with that folder (it is also remembered).</summary>
    public static string? StartFolder { get; private set; }

    [STAThread]
    public static int Main(string[] args)
    {
        // SANITIZATION_SETTINGS_DIR: alternate settings folder (used for testing).
        var dir = Environment.GetEnvironmentVariable("SANITIZATION_SETTINGS_DIR");
        if (!string.IsNullOrWhiteSpace(dir)) Core.SettingsStore.Directory_ = dir;
        var i = Array.FindIndex(args, a => a.Equals("--scan", StringComparison.OrdinalIgnoreCase));
        if (i >= 0 && i + 1 < args.Length && Directory.Exists(args[i + 1])) StartFolder = Path.GetFullPath(args[i + 1]);

        // One window per settings folder (a test run with SANITIZATION_SETTINGS_DIR never blocks your normal instance).
        var key = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(Core.SettingsStore.Directory_.ToLowerInvariant())))[..12];
        using var single = new Mutex(true, @"Local\Sanitization_SingleInstance_" + key, out var first);
        if (!first) return 0;
        return BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
    }

    public static AppBuilder BuildAvaloniaApp() => AppBuilder.Configure<App>().UsePlatformDetect().WithInterFont().LogToTrace();
}
