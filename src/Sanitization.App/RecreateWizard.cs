using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Shapes;
using Avalonia.Layout;
using Avalonia.Media;
using Sanitization.Core;

namespace Sanitization.App;

/// <summary>
/// Red step-by-step guide: delete the GitHub repo, create it again empty, then the app pushes the clean history.
/// The pictures are drawn (not screenshots), so they don't go stale when GitHub changes its look.
/// </summary>
public sealed class RecreateWizard : Window
{
    private readonly ProjectInfo _p;
    private readonly GitHubRepoRef _repo;
    private readonly DateTimeOffset _startedAt = DateTimeOffset.UtcNow.AddMinutes(-1);
    private readonly ContentControl _page = new();
    private readonly TextBlock _stepLabel = Ui.Text("", 12.5, FontWeight.SemiBold, "#fecaca");
    private readonly TextBlock _feedback = Ui.Text("", 13, FontWeight.SemiBold);
    private readonly Button _back, _next;
    private readonly StackPanel _dots = new() { Orientation = Orientation.Horizontal, Spacing = 8, VerticalAlignment = VerticalAlignment.Center };
    private int _step;
    private bool _done, _busy;
    private string _visibility = "private";
    private const int Steps = 4;

    public RecreateWizard(ProjectInfo project)
    {
        _p = project;
        _repo = project.GitHub ?? throw new InvalidOperationException("Not a GitHub repository.");
        Title = "Delete & recreate " + _repo.FullName;
        Width = 980;
        Height = 820;
        MinHeight = 640;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ShowInTaskbar = false;

        _back = Ui.Button("◀  Back", "", () => Go(_step - 1));
        _next = Ui.Button("Next  ▶", "Primary", async () => await NextAsync());
        var cancel = Ui.Button("Close", "", () => Close(_done));

        var footer = new Grid { ColumnDefinitions = new ColumnDefinitions("Auto,*,Auto"), Margin = new Thickness(24, 12, 24, 18) };
        footer.Children.Add(cancel);
        var right = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 10 };
        right.Children.Add(_back);
        right.Children.Add(_next);
        Grid.SetColumn(right, 2);
        footer.Children.Add(right);
        var middle = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 12, HorizontalAlignment = HorizontalAlignment.Center };
        middle.Children.Add(_dots);
        Grid.SetColumn(middle, 1);
        footer.Children.Add(middle);

        var header = new Border
        {
            Background = Ui.Brush("#4c1d24"), BorderBrush = Ui.Brush("#ef4444"), BorderThickness = new Thickness(0, 0, 0, 4), Padding = new Thickness(24, 16),
        };
        var hs = new StackPanel { Spacing = 3 };
        hs.Children.Add(Ui.Text("⛔  Complete clean-up: delete and recreate " + _repo.FullName, 20, FontWeight.Bold));
        hs.Children.Add(Ui.Text("A force-push hides old commits, but GitHub can still serve them by direct link, from forks and from pull requests. " +
                                "Recreating the repo is the only way to remove them completely.", 13, color: "#fecaca"));
        hs.Children.Add(_stepLabel);
        header.Child = hs;

        var root = new DockPanel();
        DockPanel.SetDock(header, Dock.Top);
        DockPanel.SetDock(footer, Dock.Bottom);
        root.Children.Add(header);
        root.Children.Add(footer);
        var feedbackBorder = new Border { Padding = new Thickness(24, 0, 24, 4), Child = _feedback };
        DockPanel.SetDock(feedbackBorder, Dock.Bottom);
        root.Children.Add(feedbackBorder);
        root.Children.Add(new ScrollViewer { Content = _page, Padding = new Thickness(24, 16) });
        Content = root;
        Opened += async (_, _) =>
        {
            var info = await GitHubService.GetRepoAsync(_repo);
            if (info.Exists && info.Visibility.Length > 0) _visibility = info.Visibility.ToLowerInvariant();
            Go(0);
        };
        Closing += (_, e) =>
        {
            if (_busy) e.Cancel = true;
        };
    }

    private void Go(int step)
    {
        _step = Math.Clamp(step, 0, Steps - 1);
        _feedback.Text = "";
        _back.IsEnabled = _step > 0 && !_done;
        _stepLabel.Text = $"Step {_step + 1} of {Steps}";
        _dots.Children.Clear();
        for (var i = 0; i < Steps; i++)
            _dots.Children.Add(new Border { Width = i == _step ? 28 : 10, Height = 10, CornerRadius = new CornerRadius(5), Background = Ui.Brush(i <= _step ? "#ef4444" : "#475569") });
        _page.Content = _step switch
        {
            0 => PageBefore(),
            1 => PageDelete(),
            2 => PageCreate(),
            _ => PagePush(),
        };
        _next.Content = _step switch { 0 => "I'm ready  ▶", 1 => "I deleted it  ▶", 2 => "I created it  ▶", _ => _done ? "Finish" : "⬆  Push everything now" };
        _next.Classes.Set("Danger", _step == 3 && !_done);
        _next.Classes.Set("Primary", _step != 3 || _done);
    }

    private async Task NextAsync()
    {
        if (_busy) return;
        _busy = true;
        _next.IsEnabled = false;
        try
        {
            switch (_step)
            {
                case 0: Go(1); break;
                case 1:
                {
                    Feedback("Checking GitHub…", "#bfdbfe");
                    var info = await GitHubService.GetRepoAsync(_repo);
                    if (info.Exists && info.CreatedAt < _startedAt) Feedback($"{_repo.FullName} still exists on GitHub. Finish deleting it first (Settings → Danger Zone → Delete this repository).", "#fca5a5");
                    else Go(2);
                    break;
                }
                case 2:
                {
                    Feedback("Checking GitHub…", "#bfdbfe");
                    var info = await GitHubService.GetRepoAsync(_repo);
                    if (!info.Exists) Feedback($"I can't find {_repo.FullName} yet. Create it (step above), then click again.", "#fca5a5");
                    else if (info.CreatedAt < _startedAt) Feedback("That still looks like the OLD repository (it was created before this guide started). Delete it first: go back one step.", "#fca5a5");
                    else Go(3);
                    break;
                }
                default:
                    if (_done) { Close(true); break; }
                    Feedback("Pushing all branches and tags… this can take a minute.", "#bfdbfe");
                    var (ok, log) = await Task.Run(() => GitHubService.ForcePushAsync(_p.Path, lease: false));
                    if (ok)
                    {
                        _done = true;
                        Go(3);
                        Feedback($"✔  Done. {_repo.FullName} now holds only your cleaned history. Your own README / LICENSE / .gitignore were kept; GitHub's auto-created ones (if any) were replaced.", "#86efac");
                    }
                    else Feedback("Push failed: " + log.Trim(), "#fca5a5");
                    break;
            }
        }
        finally
        {
            _busy = false;
            _next.IsEnabled = true;
        }
    }

    private void Feedback(string text, string color)
    {
        _feedback.Text = text;
        _feedback.Foreground = Ui.Brush(color);
    }

    // ------------------------------------------------------------------ pages

    private static StackPanel Steps_(params string[] lines)
    {
        var s = new StackPanel { Spacing = 8 };
        for (var i = 0; i < lines.Length; i++)
        {
            var row = new Grid { ColumnDefinitions = new ColumnDefinitions("34,*") };
            row.Children.Add(new Border
            {
                Width = 26, Height = 26, CornerRadius = new CornerRadius(13), Background = Ui.Brush("#b91c1c"), VerticalAlignment = VerticalAlignment.Top,
                Child = new TextBlock { Text = (i + 1).ToString(), Foreground = Brushes.White, FontWeight = FontWeight.Bold, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center },
            });
            var t = Ui.Text(lines[i], 14);
            Grid.SetColumn(t, 1);
            row.Children.Add(t);
            s.Children.Add(row);
        }
        return s;
    }

    private Control PageBefore()
    {
        var s = new StackPanel { Spacing = 16 };
        s.Children.Add(Ui.Text("Before you start: deleting a GitHub repository also deletes these, for good:", 16, FontWeight.Bold));
        var lost = new StackPanel { Spacing = 6 };
        foreach (var l in new[] { "Issues, pull requests and their discussions", "Releases and the files attached to them (download any you want to keep)", "Stars, watchers, the wiki and GitHub Pages",
                                  "Actions secrets, webhooks and repository settings" })
            lost.Children.Add(Ui.Text("✗  " + l, 14, color: "#fecaca"));
        s.Children.Add(new Border { Background = Ui.Brush("#3b1d24"), CornerRadius = new CornerRadius(10), Padding = new Thickness(16, 12), Child = lost });
        s.Children.Add(Ui.Text("Your code is safe: every commit and file is on this PC and gets uploaded again in the last step.", 14, color: "#bbf7d0"));
        s.Children.Add(Diagram.Browser($"github.com/{_repo.FullName}/releases", Diagram.ReleasesPage()));
        var row = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 10 };
        row.Children.Add(Ui.Button("Open the Releases page", "", () => Ui.OpenUrl(GitHubService.ReleasesUrl(_repo))));
        row.Children.Add(Ui.Button("Open the Issues page", "", () => Ui.OpenUrl(_repo.Url + "/issues")));
        s.Children.Add(row);
        return s;
    }

    private Control PageDelete()
    {
        var s = new StackPanel { Spacing = 16 };
        s.Children.Add(Ui.Text("Delete the repository on GitHub", 18, FontWeight.Bold));
        s.Children.Add(Steps_(
            "Click \"Open Settings page\" below. GitHub opens the repository's Settings.",
            "Scroll all the way down to the red \"Danger Zone\".",
            "Click \"Delete this repository\", follow GitHub's prompts and type " + _repo.FullName + " to confirm.",
            "Come back here and click \"I deleted it\"."));
        s.Children.Add(Ui.Button("⚙  Open Settings page", "Danger", () => Ui.OpenUrl(GitHubService.SettingsUrl(_repo))));
        s.Children.Add(Diagram.Browser($"github.com/{_repo.FullName}/settings", Diagram.DangerZone(_repo.FullName)));
        return s;
    }

    private Control PageCreate()
    {
        var s = new StackPanel { Spacing = 16 };
        s.Children.Add(Ui.Text("Create it again, completely empty", 18, FontWeight.Bold));
        var vis = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 18 };
        var priv = new RadioButton { Content = "Private (recommended until you've checked everything)", GroupName = "vis", IsChecked = _visibility != "public" };
        var pub = new RadioButton { Content = "Public", GroupName = "vis", IsChecked = _visibility == "public" };
        priv.IsCheckedChanged += (_, _) => { if (priv.IsChecked == true) _visibility = "private"; };
        pub.IsCheckedChanged += (_, _) => { if (pub.IsChecked == true) _visibility = "public"; };
        vis.Children.Add(priv);
        vis.Children.Add(pub);
        s.Children.Add(vis);
        s.Children.Add(Steps_(
            "Click \"Open New repository page\". The name (" + _repo.Name + ") and visibility are filled in for you.",
            "Leave \"Add a README file\" UNTICKED. Leave .gitignore and license on \"None\". (Your own files are uploaded in the next step.)",
            "Click the green \"Create repository\" button.",
            "Come back here and click \"I created it\"."));
        s.Children.Add(Ui.Button("＋  Open New repository page", "Primary", () => Ui.OpenUrl(GitHubService.NewRepoUrl(_repo, _visibility))));
        s.Children.Add(Diagram.Browser("github.com/new", Diagram.NewRepoPage(_repo)));
        return s;
    }

    private Control PagePush()
    {
        var s = new StackPanel { Spacing = 16 };
        s.Children.Add(Ui.Text(_done ? "All done 🎉" : "Upload your clean code", 18, FontWeight.Bold));
        s.Children.Add(Steps_(
            "Click \"Push everything now\". I upload every branch and tag from this PC to the new, empty repository.",
            "If GitHub added a README anyway, your history wins and replaces it.",
            "When it's done, re-add anything you need: releases, the repo description, collaborators, secrets."));
        s.Children.Add(Diagram.Browser($"github.com/{_repo.FullName}", Diagram.PushedPage(_repo, _done)));
        return s;
    }
}

/// <summary>Drawn mock-ups of GitHub pages with the important button highlighted.</summary>
internal static class Diagram
{
    private static Border Bar(double width, double height = 10, string color = "#334155") =>
        new() { Width = width, Height = height, CornerRadius = new CornerRadius(5), Background = Ui.Brush(color), HorizontalAlignment = HorizontalAlignment.Left };

    private static Border Highlight(Control child, string label)
    {
        var stack = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 12 };
        stack.Children.Add(new Border
        {
            BorderBrush = Ui.Brush("#facc15"), BorderThickness = new Thickness(3), CornerRadius = new CornerRadius(9), Padding = new Thickness(3),
            BoxShadow = BoxShadows.Parse("0 0 14 2 #99facc15"), Child = child,
        });
        stack.Children.Add(new TextBlock { Text = "◀  " + label, Foreground = Ui.Brush("#facc15"), FontWeight = FontWeight.Bold, FontSize = 15, VerticalAlignment = VerticalAlignment.Center });
        return new Border { Child = stack };
    }

    private static Border FakeButton(string text, string bg, string fg = "#ffffff", string? border = null) => new()
    {
        Background = Ui.Brush(bg), BorderBrush = Ui.Brush(border ?? bg), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(6), Padding = new Thickness(14, 6),
        Child = new TextBlock { Text = text, Foreground = Ui.Brush(fg), FontWeight = FontWeight.SemiBold, FontSize = 13 },
    };

    public static Control Browser(string url, Control page)
    {
        var top = new Grid { ColumnDefinitions = new ColumnDefinitions("Auto,*"), Margin = new Thickness(12, 8) };
        var dots = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 6, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 12, 0) };
        foreach (var c in new[] { "#ef4444", "#eab308", "#22c55e" }) dots.Children.Add(new Ellipse { Width = 11, Height = 11, Fill = Ui.Brush(c) });
        top.Children.Add(dots);
        var address = new Border
        {
            Background = Ui.Brush("#0b1220"), CornerRadius = new CornerRadius(14), Padding = new Thickness(14, 5),
            Child = new TextBlock { Text = "🔒  https://" + url, Foreground = Ui.Brush("#cbd5e1"), FontSize = 12.5 },
        };
        Grid.SetColumn(address, 1);
        top.Children.Add(address);
        var stack = new StackPanel();
        stack.Children.Add(new Border { Background = Ui.Brush("#1f2937"), CornerRadius = new CornerRadius(12, 12, 0, 0), Child = top });
        stack.Children.Add(new Border { Background = Ui.Brush("#0d1117"), CornerRadius = new CornerRadius(0, 0, 12, 12), Padding = new Thickness(22, 18), Child = page });
        return new Border { BorderBrush = Ui.Brush("#475569"), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(12), Child = stack, MaxWidth = 860, HorizontalAlignment = HorizontalAlignment.Left };
    }

    public static Control ReleasesPage()
    {
        var s = new StackPanel { Spacing = 12 };
        s.Children.Add(Ui.Text("Releases", 18, FontWeight.Bold, "#e6edf3"));
        for (var i = 0; i < 2; i++)
        {
            var card = new StackPanel { Spacing = 8 };
            card.Children.Add(Ui.Text(i == 0 ? "v2.1  · Latest" : "v2.0", 14, FontWeight.SemiBold, "#58a6ff"));
            card.Children.Add(Bar(420));
            var asset = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 10 };
            asset.Children.Add(Ui.Text("📦  App-setup.exe", 13, color: "#e6edf3", wrap: false));
            asset.Children.Add(Ui.Text("⬇", 14, FontWeight.Bold, "#58a6ff", false));
            card.Children.Add(i == 0 ? Highlight(asset, "download what you want to keep") : asset);
            s.Children.Add(new Border { BorderBrush = Ui.Brush("#30363d"), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(8), Padding = new Thickness(14, 10), Child = card });
        }
        return s;
    }

    public static Control DangerZone(string fullName)
    {
        var grid = new Grid { ColumnDefinitions = new ColumnDefinitions("170,24,*") };
        var side = new StackPanel { Spacing = 10 };
        side.Children.Add(Ui.Text("General", 13, FontWeight.SemiBold, "#e6edf3"));
        foreach (var x in new[] { "Collaborators", "Branches", "Actions", "Webhooks", "Secrets" }) side.Children.Add(Ui.Text(x, 13, color: "#8b949e"));
        grid.Children.Add(new Border { BorderBrush = Ui.Brush("#30363d"), BorderThickness = new Thickness(0, 0, 1, 0), Child = side });
        var main = new StackPanel { Spacing = 12 };
        main.Children.Add(Ui.Text("General", 18, FontWeight.Bold, "#e6edf3"));
        main.Children.Add(Bar(380));
        main.Children.Add(Bar(300));
        main.Children.Add(Ui.Text("⋮   scroll down to the bottom   ⋮", 12, color: "#8b949e"));
        main.Children.Add(Ui.Text("Danger Zone", 16, FontWeight.Bold, "#f85149"));
        var zone = new StackPanel();
        foreach (var (title, isDelete) in new[] { ("Change repository visibility", false), ("Transfer ownership", false), ("Archive this repository", false), ("Delete this repository", true) })
        {
            var row = new Grid { ColumnDefinitions = new ColumnDefinitions("*,Auto"), Margin = new Thickness(14, 10) };
            row.Children.Add(Ui.Text(title, 13, FontWeight.SemiBold, "#e6edf3"));
            Control button = FakeButton(isDelete ? "Delete this repository" : title.Split(' ')[0], "#21262d", "#f85149", "#30363d");
            if (isDelete) button = Highlight(button, "click this");
            Grid.SetColumn(button, 1);
            row.Children.Add(button);
            zone.Children.Add(new Border { BorderBrush = Ui.Brush("#30363d"), BorderThickness = new Thickness(0, 0, 0, isDelete ? 0 : 1), Child = row });
        }
        main.Children.Add(new Border { BorderBrush = Ui.Brush("#f85149"), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(8), Child = zone });
        var confirm = new StackPanel { Spacing = 8 };
        confirm.Children.Add(Ui.Text("Then GitHub asks you to confirm:", 12.5, color: "#8b949e"));
        confirm.Children.Add(Ui.Text($"To confirm, type \"{fullName}\" in the box below", 13, color: "#e6edf3"));
        confirm.Children.Add(new Border { BorderBrush = Ui.Brush("#30363d"), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(6), Padding = new Thickness(10, 5), Width = 320, HorizontalAlignment = HorizontalAlignment.Left, Child = Ui.Text(fullName, 13, color: "#e6edf3") });
        confirm.Children.Add(Highlight(FakeButton("Delete this repository", "#da3633"), "final click"));
        main.Children.Add(new Border { Background = Ui.Brush("#161b22"), CornerRadius = new CornerRadius(8), Padding = new Thickness(14, 12), Margin = new Thickness(0, 8, 0, 0), Child = confirm });
        Grid.SetColumn(main, 2);
        grid.Children.Add(main);
        return grid;
    }

    public static Control NewRepoPage(GitHubRepoRef repo)
    {
        var s = new StackPanel { Spacing = 12 };
        s.Children.Add(Ui.Text("Create a new repository", 18, FontWeight.Bold, "#e6edf3"));
        var names = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 10 };
        names.Children.Add(new Border { BorderBrush = Ui.Brush("#30363d"), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(6), Padding = new Thickness(10, 5), Child = Ui.Text(repo.Owner, 13, color: "#e6edf3") });
        names.Children.Add(Ui.Text("/", 16, FontWeight.Bold, "#8b949e"));
        names.Children.Add(new Border { BorderBrush = Ui.Brush("#30363d"), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(6), Padding = new Thickness(10, 5), Child = Ui.Text(repo.Name, 13, color: "#e6edf3") });
        s.Children.Add(names);
        s.Children.Add(Ui.Text("○ Public     ● Private", 13, color: "#e6edf3"));
        var readme = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8 };
        readme.Children.Add(new Border { Width = 16, Height = 16, BorderBrush = Ui.Brush("#8b949e"), BorderThickness = new Thickness(1.5), CornerRadius = new CornerRadius(3) });
        readme.Children.Add(Ui.Text("Add a README file", 13, color: "#e6edf3", wrap: false));
        s.Children.Add(Highlight(readme, "leave this OFF"));
        s.Children.Add(Ui.Text("Add .gitignore:  None        Choose a license:  None", 13, color: "#e6edf3"));
        s.Children.Add(Highlight(FakeButton("Create repository", "#238636"), "then click this"));
        return s;
    }

    public static Control PushedPage(GitHubRepoRef repo, bool done)
    {
        var s = new StackPanel { Spacing = 10 };
        s.Children.Add(Ui.Text(repo.FullName, 16, FontWeight.Bold, "#58a6ff"));
        if (!done)
        {
            s.Children.Add(Ui.Text("Quick setup — if you've done this kind of thing before", 13, color: "#8b949e"));
            s.Children.Add(Ui.Text("This repository is empty. Sanitization uploads everything for you.", 13, color: "#e6edf3"));
        }
        else
        {
            foreach (var f in new[] { "📁 src", "📄 README.md", "📄 .gitignore", "📄 LICENSE" }) s.Children.Add(Ui.Text(f, 13, color: "#e6edf3"));
            s.Children.Add(Ui.Text("✔ Clean history uploaded", 13, FontWeight.SemiBold, "#3fb950"));
        }
        return s;
    }
}
