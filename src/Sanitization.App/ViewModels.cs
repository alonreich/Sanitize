using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Windows.Input;
using Avalonia.Media;
using Avalonia.Media.Immutable;
using Sanitization.Core;

namespace Sanitization.App;

public abstract class ViewModelBase : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    protected void Raise([CallerMemberName] string? name = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    protected bool Set<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return false;
        field = value;
        Raise(name);
        return true;
    }
}

public sealed class RelayCommand(Func<Task> run, Func<bool>? canRun = null) : ICommand
{
    private bool _busy;
    public RelayCommand(Action run, Func<bool>? canRun = null) : this(() => { run(); return Task.CompletedTask; }, canRun) { }
    public event EventHandler? CanExecuteChanged;
    public bool CanExecute(object? parameter) => !_busy && (canRun?.Invoke() ?? true);
    public void Refresh() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);

    public async void Execute(object? parameter)
    {
        if (!CanExecute(parameter)) return;
        _busy = true;
        Refresh();
        try { await run(); }
        catch (Exception e) { await MainViewModel.Current.ShowErrorAsync("Something went wrong", e.Message); }
        finally
        {
            _busy = false;
            Refresh();
        }
    }
}

public static class Palette
{
    public static readonly IBrush Critical = new ImmutableSolidColorBrush(Color.Parse("#ef4444"));
    public static readonly IBrush High = new ImmutableSolidColorBrush(Color.Parse("#f97316"));
    public static readonly IBrush Medium = new ImmutableSolidColorBrush(Color.Parse("#eab308"));
    public static readonly IBrush Low = new ImmutableSolidColorBrush(Color.Parse("#94a3b8"));
    public static readonly IBrush CriticalSoft = new ImmutableSolidColorBrush(Color.Parse("#4a1f27"));
    public static readonly IBrush HighSoft = new ImmutableSolidColorBrush(Color.Parse("#4a2c1a"));
    public static readonly IBrush MediumSoft = new ImmutableSolidColorBrush(Color.Parse("#433a17"));
    public static readonly IBrush LowSoft = new ImmutableSolidColorBrush(Color.Parse("#334155"));
    public static readonly IBrush ChipFile = new ImmutableSolidColorBrush(Color.Parse("#1e3a5f"));
    public static readonly IBrush ChipHistory = new ImmutableSolidColorBrush(Color.Parse("#3b2a5c"));
    public static readonly IBrush ChipRemote = new ImmutableSolidColorBrush(Color.Parse("#5a2330"));
    public static readonly IBrush ChipIgnored = new ImmutableSolidColorBrush(Color.Parse("#4d3d12"));
    public static readonly IBrush ChipNeutral = new ImmutableSolidColorBrush(Color.Parse("#3a4a61"));
    public static readonly IBrush ChipDone = new ImmutableSolidColorBrush(Color.Parse("#14532d"));
    public static readonly IBrush Text = new ImmutableSolidColorBrush(Color.Parse("#f1f5f9"));
    public static readonly IBrush Warning = new ImmutableSolidColorBrush(Color.Parse("#3d3214"));
    public static readonly IBrush WarningText = new ImmutableSolidColorBrush(Color.Parse("#fde68a"));
    public static readonly IBrush Danger = new ImmutableSolidColorBrush(Color.Parse("#3b1d24"));
    public static readonly IBrush DangerText = new ImmutableSolidColorBrush(Color.Parse("#fecaca"));
    public static readonly IBrush Info = new ImmutableSolidColorBrush(Color.Parse("#1c3352"));
    public static readonly IBrush InfoText = new ImmutableSolidColorBrush(Color.Parse("#bfdbfe"));
    public static readonly IBrush Success = new ImmutableSolidColorBrush(Color.Parse("#173d2a"));
    public static readonly IBrush SuccessText = new ImmutableSolidColorBrush(Color.Parse("#bbf7d0"));

    public static IBrush For(Severity s) => s switch { Severity.Critical => Critical, Severity.High => High, Severity.Medium => Medium, _ => Low };
    public static IBrush SoftFor(Severity s) => s switch { Severity.Critical => CriticalSoft, Severity.High => HighSoft, Severity.Medium => MediumSoft, _ => LowSoft };
    public static string Icon(Severity s) => s switch { Severity.Critical => "●", Severity.High => "●", Severity.Medium => "●", _ => "○" };
}

public sealed record ChipViewModel(string Text, IBrush Background);

public sealed record BannerViewModel(string Text, IBrush Background, IBrush Foreground);

public sealed class FindingViewModel : ViewModelBase
{
    private bool _isSelected;
    public Finding Finding { get; }
    public ProjectViewModel Project { get; }

    public FindingViewModel(Finding f, ProjectViewModel project)
    {
        Finding = f;
        Project = project;
        foreach (var text in SeverityText.Chips(f))
        {
            var bg = text.StartsWith("File", StringComparison.Ordinal) ? Palette.ChipFile
                : text.StartsWith("Git history", StringComparison.Ordinal) || text.StartsWith("Commit", StringComparison.Ordinal) || text.StartsWith("in ", StringComparison.Ordinal) ? Palette.ChipHistory
                : text == "On GitHub" ? Palette.ChipRemote
                : text.StartsWith("Never committed", StringComparison.Ordinal) ? Palette.ChipIgnored
                : text.StartsWith("Removed here", StringComparison.Ordinal) ? Palette.ChipDone
                : Palette.ChipNeutral;
            Chips.Add(new ChipViewModel(text == "On GitHub" && project.Info.GitHub is null ? "On the remote" : text, bg));
        }
        FixCommand = new RelayCommand(() => MainViewModel.Current.FixAsync([this], "this item"), () => CanFix);
        IgnoreCommand = new RelayCommand(() => MainViewModel.Current.IgnoreAsync(this));
        OpenCommand = new RelayCommand(Open, () => CanOpen);
    }

    public ObservableCollection<ChipViewModel> Chips { get; } = [];
    public string Category => Finding.Category;
    public string Why => Finding.Why;
    public string Value => Finding.Value.Length > 320 ? Finding.Value[..320] + " …" : Finding.Value;
    public string? Snippet => Finding.Snippet is { Length: > 0 } s && s != "commit message" && s != Finding.Value ? s : null;
    public bool HasSnippet => Snippet is not null;
    public IBrush SeverityBrush => Palette.For(Finding.Severity);
    public bool CanFix => Finding.CanFix;
    public bool ShowReplacement => Finding.CanFix && Finding.Replacement is not null;
    public bool ShowFixText => !ShowReplacement;
    public string FixText => Finding.CanFix || Finding.OnlyOnRemote ? Finding.FixDescription : Finding.NoFixReason ?? "";
    public string FixDescription => Finding.FixDescription;
    public bool IsLow => Finding.Severity == Severity.Low;

    public string Location
    {
        get
        {
            var f = Finding;
            if (f.Kind == FindingKind.CommitIdentity) return "Commit author / committer";
            if (f.Kind == FindingKind.RemoteUrl) return "Git remote settings";
            if (f.Kind == FindingKind.GitConfig) return "This repo's git settings";
            if (f.RelativePath.Length == 0) return "Commit messages";
            return f.Lines.Count > 0 ? $"{f.RelativePath}  ·  line {string.Join(", ", f.Lines.Order().Take(6))}{(f.Lines.Count > 6 ? "…" : "")}" : f.RelativePath;
        }
    }

    public string? Replacement
    {
        get => Finding.Replacement;
        set
        {
            if (Finding.Replacement == value) return;
            Finding.Replacement = value;
            Raise();
        }
    }

    public bool IsSelected
    {
        get => _isSelected;
        set
        {
            if (value && !CanFix) value = false;
            if (Set(ref _isSelected, value)) Project.OnSelectionChanged();
        }
    }

    public string FullPath => Path.Combine(Finding.ProjectPath, Finding.RelativePath.Replace('/', '\\'));
    public bool CanOpen => Finding.RelativePath.Length > 0 && !Finding.RelativePath.StartsWith("remote ", StringComparison.Ordinal) && File.Exists(FullPath);
    public RelayCommand FixCommand { get; }
    public RelayCommand IgnoreCommand { get; }
    public RelayCommand OpenCommand { get; }

    private void Open()
    {
        var psi = new ProcessStartInfo("explorer.exe") { UseShellExecute = false };
        psi.ArgumentList.Add("/select," + FullPath);
        Process.Start(psi);
    }

    public void SetSelectedSilently(bool v)
    {
        if (v && !CanFix) v = false;
        Set(ref _isSelected, v, nameof(IsSelected));
    }
}

public sealed class SeverityGroupViewModel : ViewModelBase
{
    private bool _isFilteredIn = true;
    public Severity Severity { get; }
    public ProjectViewModel Project { get; }
    public ObservableCollection<FindingViewModel> Items { get; } = [];

    public SeverityGroupViewModel(Severity s, ProjectViewModel project)
    {
        Severity = s;
        Project = project;
        Items.CollectionChanged += (_, _) => { Raise(nameof(Title)); Raise(nameof(IsVisible)); Raise(nameof(Count)); };
    }

    public int Count => Items.Count;
    public string Title => $"{SeverityText.Title(Severity)}  ·  {Items.Count}";
    public string LowHeader => $"Probably fine · {Items.Count}  —  click to review (test / sample data, files that can't be inspected)";
    public string Subtitle => SeverityText.Subtitle(Severity);
    public IBrush Brush => Palette.For(Severity);
    public IBrush SoftBrush => Palette.SoftFor(Severity);
    public bool IsVisible => _isFilteredIn && Items.Count > 0;

    public bool IsFilteredIn
    {
        get => _isFilteredIn;
        set { if (Set(ref _isFilteredIn, value)) Raise(nameof(IsVisible)); }
    }

    public bool? AllSelected
    {
        get
        {
            var fixable = Items.Where(i => i.CanFix).ToList();
            if (fixable.Count == 0 || fixable.All(i => !i.IsSelected)) return false;
            return fixable.All(i => i.IsSelected) ? true : null;
        }
        set
        {
            var v = value ?? false;
            foreach (var i in Items) i.SetSelectedSilently(v);
            Project.OnSelectionChanged();
        }
    }

    public void RaiseSelection() => Raise(nameof(AllSelected));
}

public sealed class ProjectViewModel : ViewModelBase
{
    private bool _isScanning = true;
    private bool _isExpanded = true;
    private string _status = "Waiting…";
    private string _visibility = "";

    public ProjectInfo Info { get; private set; }
    public ProjectScanResult? Result { get; private set; }
    public SeverityGroupViewModel Critical { get; }
    public SeverityGroupViewModel High { get; }
    public SeverityGroupViewModel Medium { get; }
    public SeverityGroupViewModel Low { get; }
    public ObservableCollection<ChipViewModel> Chips { get; } = [];
    public ObservableCollection<BannerViewModel> Banners { get; } = [];

    public ProjectViewModel(ProjectInfo info)
    {
        Info = info;
        Critical = new SeverityGroupViewModel(Severity.Critical, this);
        High = new SeverityGroupViewModel(Severity.High, this);
        Medium = new SeverityGroupViewModel(Severity.Medium, this);
        Low = new SeverityGroupViewModel(Severity.Low, this);
        FixSelectedCommand = new RelayCommand(() => MainViewModel.Current.FixAsync(SelectedItems.ToList(), "the selected items"), () => SelectedCount > 0 && !IsScanning);
        FixAllCommand = new RelayCommand(() => MainViewModel.Current.FixAsync(MainItems.Where(i => i.CanFix).ToList(), $"everything in {Name}"), () => FixableCount > 0 && !IsScanning);
        PushCommand = new RelayCommand(() => MainViewModel.Current.PushAsync(this), () => CanPush && !IsScanning);
        ToggleCommand = new RelayCommand(() => IsExpanded = !IsExpanded);
        RescanCommand = new RelayCommand(() => MainViewModel.Current.RescanProjectsAsync([this]), () => !IsScanning);
    }

    public string Name => Info.Name;
    public string PathText => Info.TopLevelOnly ? Info.Path + "  (only the files directly in this folder)" : Info.Path;
    public IEnumerable<SeverityGroupViewModel> Groups => [Critical, High, Medium, Low];
    public IEnumerable<FindingViewModel> AllItems => Groups.SelectMany(g => g.Items);
    public IEnumerable<FindingViewModel> MainItems => new[] { Critical, High, Medium }.SelectMany(g => g.Items);
    public IEnumerable<FindingViewModel> SelectedItems => AllItems.Where(i => i.IsSelected);
    public int SelectedCount => SelectedItems.Count();
    public int FixableCount => MainItems.Count(i => i.CanFix);
    public int TotalCount => AllItems.Count();
    public bool HasFindings => TotalCount > 0;
    public bool IsClean => !IsScanning && TotalCount == 0;
    public bool ShowBody => IsExpanded && !IsScanning && HasFindings;
    public bool HasLow => Low.Items.Count > 0;
    public bool CanPush => Info.IsGit && Info.OriginUrl is { Length: > 0 } && (Info.LocalOnlyCommits > 0 || Info.NeedsForcePush || AllItems.Any(i => i.Finding.OnlyOnRemote));
    public bool HighlightPush => CanPush && (Info.NeedsForcePush || AllItems.Any(i => i.Finding.OnlyOnRemote));
    public string FixSelectedText => SelectedCount > 0 ? $"Fix selected ({SelectedCount})" : "Fix selected";
    public string FixAllText => $"Fix all in this project ({FixableCount})";
    public string PushText => Info.GitHub is not null ? "Push to GitHub" : "Push to remote";
    public string ChevronText => IsExpanded ? "▾" : "▸";
    public string CriticalCountText => Critical.Count.ToString();
    public string HighCountText => High.Count.ToString();
    public string MediumCountText => Medium.Count.ToString();
    public string LowCountText => Low.Count.ToString();
    public bool ShowCounts => !IsScanning && HasFindings;
    public bool IsLoose => Info.TopLevelOnly;

    public bool IsScanning
    {
        get => _isScanning;
        set
        {
            if (!Set(ref _isScanning, value)) return;
            RaiseAll();
        }
    }

    public string Status { get => _status; set => Set(ref _status, value); }

    public bool IsExpanded
    {
        get => _isExpanded;
        set
        {
            if (!Set(ref _isExpanded, value)) return;
            Raise(nameof(ShowBody));
            Raise(nameof(ChevronText));
        }
    }

    public string Visibility
    {
        get => _visibility;
        set
        {
            if (!Set(ref _visibility, value)) return;
            RebuildChips();
        }
    }

    public RelayCommand FixSelectedCommand { get; }
    public RelayCommand FixAllCommand { get; }
    public RelayCommand PushCommand { get; }
    public RelayCommand ToggleCommand { get; }
    public RelayCommand RescanCommand { get; }

    public void Load(ProjectScanResult result, Func<Severity, bool> filter)
    {
        Result = result;
        Info = result.Project;
        foreach (var g in Groups) g.Items.Clear();
        foreach (var f in result.Findings)
        {
            var group = f.Severity switch { Severity.Critical => Critical, Severity.High => High, Severity.Medium => Medium, _ => Low };
            group.Items.Add(new FindingViewModel(f, this));
        }
        foreach (var g in Groups) g.IsFilteredIn = filter(g.Severity);
        RebuildChips();
        RebuildBanners();
        IsExpanded = HasFindings;
        IsScanning = false;
        Status = "";
        RaiseAll();
    }

    public void Remove(FindingViewModel vm)
    {
        foreach (var g in Groups) g.Items.Remove(vm);
        RaiseAll();
        OnSelectionChanged();
    }

    private void RebuildChips()
    {
        Chips.Clear();
        if (Info.TopLevelOnly) { Chips.Add(new ChipViewModel("Loose files", Palette.ChipNeutral)); return; }
        if (!Info.IsGit) { Chips.Add(new ChipViewModel("Not a git repo", Palette.ChipNeutral)); return; }
        Chips.Add(new ChipViewModel(string.IsNullOrEmpty(Info.Branch) ? "Git" : $"Git · {Info.Branch}", Palette.ChipFile));
        if (Info.GitHub is not null)
            Chips.Add(new ChipViewModel(Visibility.Length > 0 ? $"GitHub · {Info.GitHub.FullName} · {Visibility.ToLowerInvariant()}" : $"GitHub · {Info.GitHub.FullName}",
                Visibility.Equals("public", StringComparison.OrdinalIgnoreCase) ? Palette.ChipRemote : Palette.ChipHistory));
        else if (string.IsNullOrEmpty(Info.OriginUrl)) Chips.Add(new ChipViewModel("No remote", Palette.ChipNeutral));
        if (Info.HasUncommittedChanges) Chips.Add(new ChipViewModel("Uncommitted changes", Palette.ChipIgnored));
        if (Info.LocalOnlyCommits > 0) Chips.Add(new ChipViewModel($"{Info.LocalOnlyCommits} commit(s) not pushed", Palette.ChipNeutral));
    }

    private void RebuildBanners()
    {
        Banners.Clear();
        var remote = Info.GitHub is not null ? "GitHub" : "the remote";
        if (Info.NeedsForcePush || AllItems.Any(i => i.Finding.OnlyOnRemote))
            Banners.Add(new BannerViewModel($"The history here is clean, but {remote} still has the old commits. Click \"{PushText}\" to finish.", Palette.Warning, Palette.WarningText));
        if (Info.HasUncommittedChanges && AllItems.Any(i => FixPlanner.TouchesHistory(i.Finding)))
            Banners.Add(new BannerViewModel("This repo has uncommitted changes, so items in git history can't be removed yet. Commit or stash your changes first. Files can still be fixed now.", Palette.Info, Palette.InfoText));
        foreach (var n in Info.Notes.Take(3)) Banners.Add(new BannerViewModel(n, Palette.Info, Palette.InfoText));
    }

    public void OnSelectionChanged()
    {
        foreach (var g in Groups) g.RaiseSelection();
        Raise(nameof(SelectedCount));
        Raise(nameof(FixSelectedText));
        FixSelectedCommand.Refresh();
        MainViewModel.Current.OnSelectionChanged();
    }

    public void ApplyFilter(Func<Severity, bool> filter)
    {
        foreach (var g in Groups) g.IsFilteredIn = filter(g.Severity);
    }

    private void RaiseAll()
    {
        foreach (var n in new[] { nameof(IsClean), nameof(ShowBody), nameof(HasFindings), nameof(TotalCount), nameof(FixableCount), nameof(FixAllText),
                     nameof(CanPush), nameof(HighlightPush), nameof(PushText), nameof(HasLow), nameof(CriticalCountText), nameof(HighCountText),
                     nameof(MediumCountText), nameof(LowCountText), nameof(ShowCounts), nameof(PathText), nameof(Name) })
            Raise(n);
        FixAllCommand.Refresh();
        FixSelectedCommand.Refresh();
        PushCommand.Refresh();
        RescanCommand.Refresh();
    }
}
