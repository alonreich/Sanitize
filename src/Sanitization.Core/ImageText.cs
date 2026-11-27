using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Graphics.Imaging;
using Windows.Media.Ocr;
using Windows.Storage.Streams;

namespace Sanitization.Core;

/// <summary>Reads the text shown in screenshots / pictures with Windows' built-in OCR (no download, no network).
/// Icons and tiny images are skipped; anything that fails simply returns null.</summary>
public static class ImageText
{
    public static readonly HashSet<string> Extensions = new(StringComparer.OrdinalIgnoreCase) { ".png", ".jpg", ".jpeg", ".jpe", ".jfif", ".bmp", ".gif", ".tif", ".tiff" };
    public const int MinWidth = 120, MinHeight = 24, MaxBytes = 15 * 1024 * 1024;
    private static readonly Lazy<OcrEngine?> Engine = new(() =>
    {
        try { return OcrEngine.TryCreateFromUserProfileLanguages() ?? OcrEngine.TryCreateFromLanguage(new Windows.Globalization.Language("en-US")); }
        catch { return null; }
    });
    private static readonly SemaphoreSlim Gate = new(2);

    public static bool Available => Engine.Value is not null;

    public static bool LooksLikeImage(byte[] d) =>
        d.Length > 8 && (d[0] == 0x89 && d[1] == 0x50 && d[2] == 0x4E && d[3] == 0x47 || d[0] == 0xFF && d[1] == 0xD8 || d[0] == 0x42 && d[1] == 0x4D
                         || d[0] == 0x47 && d[1] == 0x49 && d[2] == 0x46 || d[0] == 0x49 && d[1] == 0x49 && d[2] == 0x2A || d[0] == 0x4D && d[1] == 0x4D && d[2] == 0x00);

    /// <summary>The recognised text (lines joined by newlines), or null when the picture is too small, not an image, or OCR is unavailable.</summary>
    public static async Task<string?> ReadAsync(byte[] data, CancellationToken ct)
    {
        if (data.Length > MaxBytes || !LooksLikeImage(data) || Engine.Value is not { } engine) return null;
        await Gate.WaitAsync(ct);
        try
        {
            using var stream = new InMemoryRandomAccessStream();
            await stream.WriteAsync(data.AsBuffer());
            stream.Seek(0);
            var decoder = await BitmapDecoder.CreateAsync(stream);
            if (decoder.PixelWidth < MinWidth || decoder.PixelHeight < MinHeight || decoder.PixelWidth == decoder.PixelHeight && decoder.PixelWidth <= 512) return null;
            var w = decoder.PixelWidth;
            var h = decoder.PixelHeight;
            var scale = Math.Min(1.0, OcrEngine.MaxImageDimension / (double)Math.Max(w, h));
            var transform = new BitmapTransform { ScaledWidth = (uint)Math.Max(1, w * scale), ScaledHeight = (uint)Math.Max(1, h * scale) };
            using var bitmap = await decoder.GetSoftwareBitmapAsync(BitmapPixelFormat.Bgra8, BitmapAlphaMode.Premultiplied, transform,
                ExifOrientationMode.RespectExifOrientation, ColorManagementMode.DoNotColorManage);
            var result = await engine.RecognizeAsync(bitmap);
            var text = string.Join("\n", result.Lines.Select(l => l.Text));
            return text.Trim().Length == 0 ? null : text;
        }
        catch
        {
            return null;
        }
        finally
        {
            Gate.Release();
        }
    }
}
