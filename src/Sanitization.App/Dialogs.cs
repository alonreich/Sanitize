using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Media.Immutable;
using Avalonia.Threading;
using Sanitization.Core;

namespace Sanitization.App;

internal static class Ui
{
    public static IBrush Brush(string hex) => new ImmutableSolidColorBrush(Color.Parse(hex));

    public static TextBlock Text(string text, double size = 13, FontWeight weight = FontWeight.Normal, string? color = null, bool wrap = true) => new()
    {
        Text = text, FontSize = size, FontWeight = weight, TextWrapping = wrap ? TextWrapping.Wrap : TextWrapping.NoWrap,
        Foreground = color is null ? Brush("#f1f5f9") : Brush(color),
    };

    public static Button Button(string text, string classes = "", Action? click = null)
    {
        var b = new Button { Content = text, MinWidth = 96 };
        foreach (var c in classes.Split(' ', StringSplitOptions.RemoveEmptyEntries)) b.Classes.Add(c);
        if (click is not null) b.Click += (_, _) => click();
        return b;
    }

    public static (string Bar, string Soft, string Icon) Tone(DialogTone t) => t switch
    {
        DialogTone.Danger => ("#b91c1c", "#3b1d24", "⛔"),
        DialogTone.Warning => ("#b45309", "#3d3214", "⚠"),
        DialogTone.Success => ("#15803d", "#173d2a", "✔"),
        _ => ("#2563eb", "#1c3352", "ℹ"),
    };

    public static Border Header(string title, DialogTone tone, string? subtitle = null)
    {
        var (bar, soft, icon) = Tone(tone);
        var stack = new StackPanel { Spacing = 2, VerticalAlignment = VerticalAlignment.Center };
        stack.Children.Add(Text(title, 19, FontWeight.Bold));
        if (subtitle is not null) stack.Children.Add(Text(subtitle, 12.5, color: "#cbd5e1"));
        var row = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 14 };
        row.Children.Add(new Border { Background = Brush(bar), CornerRadius = new CornerRadius(22), Width = 44, Height = 44, Child = new TextBlock { Text = icon, FontSize = 20, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center, Foreground = Brushes.White } });
        row.Children.Add(stack);
        return new Border { Background = Brush(soft), BorderBrush = Brush(bar), BorderThickness = new Thickness(0, 0, 0, 3), Padding = new Thickness(24, 18), Child = row };
    }

    public static void OpenUrl(string url)
    {
        try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(url) { UseShellExecute = true }); } catch { }
    }
}

public sealed class MessageDialog : Window
{
    private bool _done;

    public MessageDialog(DialogSpec spec)
    {
        Title = spec.Title;
        Width = 640;
        SizeToContent = SizeToContent.Height;
        CanResize = false;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ShowInTaskbar = false;
        var cancelIndex = spec.Buttons.ToList().FindIndex(b => b.IsCancel);

        var body = new StackPanel { Spacing = 12, Margin = new Thickness(24, 18, 24, 6) };
        body.Children.Add(Ui.Text(spec.Body, 14));
        if (spec.Bullets is { Count: > 0 })
        {
            var list = new StackPanel { Spacing = 8 };
            foreach (var b in spec.Bullets)
            {
                var row = new Grid { ColumnDefinitions = new ColumnDefinitions("18,*") };
                row.Children.Add(Ui.Text("•", 14, FontWeight.Bold, Ui.Tone(spec.Tone).Bar));
                var t = Ui.Text(b, 13, color: "#e2e8f0");
                Grid.SetColumn(t, 1);
                row.Children.Add(t);
                list.Children.Add(row);
            }
            body.Children.Add(new Border { Background = Ui.Brush("#273548"), CornerRadius = new CornerRadius(8), Padding = new Thickness(14, 12), Child = list });
        }
        if (spec.Footer is not null) body.Children.Add(Ui.Text(spec.Footer, 12.5, color: "#b6c2d0"));

        var buttons = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 10, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(24, 14, 24, 20) };
        for (var i = 0; i < spec.Buttons.Count; i++)
        {
            var index = i;
            var b = Ui.Button(spec.Buttons[i].Text, spec.Buttons[i].Style, () => Finish(index));
            if (spec.Buttons[i].IsCancel) b.IsCancel = true;
            buttons.Children.Add(b);
        }
        var root = new DockPanel();
        var header = Ui.Header(spec.Title, spec.Tone);
        DockPanel.SetDock(header, Dock.Top);
        DockPanel.SetDock(buttons, Dock.Bottom);
        root.Children.Add(header);
        root.Children.Add(buttons);
        root.Children.Add(body);
        Content = root;

        Closing += (_, e) =>
        {
            if (_done) return;
            e.Cancel = true;
            Dispatcher.UIThread.Post(() => Finish(cancelIndex));
        };
        KeyDown += (_, e) => { if (e.Key == Key.Escape) Finish(cancelIndex); };
    }

    private void Finish(int index)
    {
        if (_done) return;
        _done = true;
        Close(index);
    }
}

public sealed class PrivateInfoWindow : Window
{
    private readonly AppSettings _settings;
    private readonly StackPanel _rows = new() { Spacing = 8 };
    private readonly List<(TextBox Value, TextBox Replacement)> _editors = [];

    public PrivateInfoWindow(AppSettings settings, MachineIdentity? id)
    {
        _settings = settings;
        Title = "My private info";
        Width = 820;
        Height = 700;
        MinHeight = 480;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ShowInTaskbar = false;

        var body = new StackPanel { Spacing = 14, Margin = new Thickness(24, 18) };
        body.Children.Add(Ui.Text("Add anything that's yours and must never go public: e-mail addresses, phone numbers, your home address, your real name, " +
                                  "employer or customer names, server names, internal URLs. I'll look for each one in every file and in all of git history.", 14));
        body.Children.Add(new Border
        {
            Background = Ui.Brush("#173d2a"), CornerRadius = new CornerRadius(8), Padding = new Thickness(12, 8),
            Child = Ui.Text("🔒  Stored encrypted for your Windows account only, in " + SettingsStore.Directory_ + ". Never written into any project or git repo.", 12.5, color: "#bbf7d0"),
        });

        var head = new Grid { ColumnDefinitions = new ColumnDefinitions("*,12,260,12,90") };
        head.Children.Add(Ui.Text("Private value", 12, FontWeight.SemiBold, "#b6c2d0"));
        var h2 = Ui.Text("Replace it with", 12, FontWeight.SemiBold, "#b6c2d0");
        Grid.SetColumn(h2, 2);
        head.Children.Add(h2);
        body.Children.Add(head);
        foreach (var t in settings.PrivateTerms) AddRow(t.Value, t.Replacement);
        if (settings.PrivateTerms.Count == 0)
        {
            if (id is not null && id.GlobalGitEmail.Contains('@') && !id.GlobalGitEmail.Contains("noreply", StringComparison.OrdinalIgnoreCase)) AddRow(id.GlobalGitEmail, "user@example.com");
            else AddRow("", "REDACTED");
        }
        body.Children.Add(_rows);
        body.Children.Add(Ui.Button("＋  Add another", "Small", () => AddRow("", "REDACTED")));

        if (id is not null)
        {
            var detected = new StackPanel { Spacing = 4 };
            detected.Children.Add(Ui.Text("Already detected automatically (no need to add these):", 12.5, FontWeight.SemiBold, "#b6c2d0"));
            foreach (var line in new[]
                     {
                         $"Windows user name: {id.UserName}", $"Computer name: {id.MachineName}",
                         id.Fqdn.Length > 0 ? $"Full network name: {id.Fqdn}" : "", id.DnsDomain.Length > 0 ? $"Domain: {id.DnsDomain}" : "",
                         id.Sid.Length > 0 ? $"Windows account ID: {id.Sid}" : "", id.GlobalGitEmail.Length > 0 ? $"Git e-mail: {id.GlobalGitEmail}" : "",
                         id.LanIps.Count > 0 ? $"Local IP: {string.Join(", ", id.LanIps)}" : "",
                     }.Where(l => l.Length > 0))
                detected.Children.Add(Ui.Text("•  " + line, 12.5, color: "#cbd5e1"));
            body.Children.Add(new Border { Background = Ui.Brush("#273548"), CornerRadius = new CornerRadius(8), Padding = new Thickness(14, 10), Child = detected });
        }

        var buttons = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 10, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(24, 12, 24, 18) };
        buttons.Children.Add(Ui.Button("Cancel", "", Close));
        buttons.Children.Add(Ui.Button("Save and re-scan", "Primary", Save));
        var root = new DockPanel();
        var header = Ui.Header("My private info", DialogTone.Info, "Things only you know about. They're always treated as High.");
        DockPanel.SetDock(header, Dock.Top);
        DockPanel.SetDock(buttons, Dock.Bottom);
        root.Children.Add(header);
        root.Children.Add(buttons);
        root.Children.Add(new ScrollViewer { Content = body });
        Content = root;
    }

    private void AddRow(string value, string replacement)
    {
        var grid = new Grid { ColumnDefinitions = new ColumnDefinitions("*,12,260,12,90") };
        var v = new TextBox { Text = value, PlaceholderText = "e.g. your e-mail address or phone number" };
        var r = new TextBox { Text = replacement, PlaceholderText = "REDACTED" };
        Grid.SetColumn(r, 2);
        var remove = Ui.Button("Remove", "Small");
        Grid.SetColumn(remove, 4);
        grid.Children.Add(v);
        grid.Children.Add(r);
        grid.Children.Add(remove);
        var pair = (v, r);
        remove.Click += (_, _) => { _rows.Children.Remove(grid); _editors.Remove(pair); };
        _editors.Add(pair);
        _rows.Children.Add(grid);
    }

    private void Save()
    {
        _settings.PrivateTerms = _editors
            .Select(e => new PrivateTerm { Value = (e.Value.Text ?? "").Trim(), Replacement = string.IsNullOrWhiteSpace(e.Replacement.Text) ? "REDACTED" : e.Replacement.Text!.Trim() })
            .Where(t => t.Value.Length >= 3)
            .GroupBy(t => t.Value, StringComparer.OrdinalIgnoreCase).Select(g => g.First()).ToList();
        Close();
    }
}

public sealed class IgnoredItemsWindow : Window
{
    private bool _changed;

    public IgnoredItemsWindow(AppSettings settings)
    {
        Title = "Ignored items";
        Width = 760;
        Height = 600;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ShowInTaskbar = false;
        var body = new StackPanel { Spacing = 10, Margin = new Thickness(24, 18) };
        if (settings.Ignored.Count == 0) body.Children.Add(Ui.Text("Nothing is ignored. Items you mark with \"Ignore\" show up here.", 14, color: "#b6c2d0"));
        foreach (var (project, values) in settings.Ignored.OrderBy(k => k.Key).ToList())
        {
            body.Children.Add(Ui.Text(project, 15, FontWeight.Bold));
            foreach (var value in values.ToList())
            {
                var row = new Grid { ColumnDefinitions = new ColumnDefinitions("*,Auto"), Margin = new Thickness(0, 0, 0, 4) };
                var t = new SelectableTextBlock { Text = value, FontFamily = new FontFamily("Cascadia Mono, Consolas, monospace"), Foreground = Ui.Brush("#fde68a"), TextWrapping = TextWrapping.Wrap, VerticalAlignment = VerticalAlignment.Center };
                var b = Ui.Button("Show it again", "Small");
                Grid.SetColumn(b, 1);
                b.Click += (_, _) =>
                {
                    settings.Unignore(project, value);
                    body.Children.Remove(row);
                    _changed = true;
                };
                row.Children.Add(t);
                row.Children.Add(b);
                body.Children.Add(new Border { Background = Ui.Brush("#273548"), CornerRadius = new CornerRadius(8), Padding = new Thickness(12, 6), Child = row });
            }
        }
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(24, 12, 24, 18) };
        buttons.Children.Add(Ui.Button("Close", "Primary", () => Close(_changed)));
        var root = new DockPanel();
        var header = Ui.Header("Ignored items", DialogTone.Info, "Marked as \"not a problem\". Stored encrypted with your settings.");
        DockPanel.SetDock(header, Dock.Top);
        DockPanel.SetDock(buttons, Dock.Bottom);
        root.Children.Add(header);
        root.Children.Add(buttons);
        root.Children.Add(new ScrollViewer { Content = body });
        Content = root;
        Closing += (_, e) =>
        {
            if (_closing) return;
            e.Cancel = true;
            _closing = true;
            Dispatcher.UIThread.Post(() => Close(_changed));
        };
    }

    private bool _closing;
}
