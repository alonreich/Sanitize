using System.Collections.ObjectModel;
using Avalonia.Threading;
using Sanitization.Core;

namespace Sanitization.App;

public enum DialogTone { Info, Warning, Danger, Success }

public sealed record DialogButton(string Text, string Style = "", bool IsCancel = false);

public sealed record DialogSpec(string Title, string Body, DialogTone Tone, IReadOnlyList<DialogButton> Buttons, IReadOnlyList<string>? Bullets = null, string? Footer = null);

/// <summary>Everything the view model needs from the window.</summary>
public interface IUi
{
    Task<int> ShowDialogAsync(DialogSpec spec);
    Task<string?> PickFolderAsync();
    Task ShowPrivateInfoAsync(AppSettings settings, MachineIdentity? id);
    Task<bool> ShowIgnoredAsync(AppSettings settings);
    Task<bool> ShowRecreateWizardAsync(ProjectViewModel project);
}

public sealed class MainViewModel : ViewModelBase
{
    public static MainViewModel Current { get; private set; } = null!;

    private readonly IUi _ui;
    private readonly AppSettings _settings;
    private readonly Stack<UndoBatch> _undo = new();
    private CancellationTokenSource? _cts;
    private MachineIdentity? _identity;
    private ToolStatus? _tools;
    private bool _isScanning, _showCritical = true, _showHigh = true, _showMedium = true, _showLow = true;
    private double _progress;
    private string _status = "", _toast = "";
    private DialogTone _toastTone;
    private int _toastId;

    public MainViewModel(IUi ui)
    {
        Current = this;
        _ui = ui;
        _settings = SettingsStore.Load();
        if (Program.StartFolder is not null && !SettingsStore.IsInsideSettings(Program.StartFolder))
        {
            _settings.ScanRoot = Program.StartFolder;
            try { SettingsStore.Save(_settings); } catch { }
        }
        ChooseFolderCommand = new RelayCommand(ChooseFolderAsync, () => !IsScanning);
        ScanCommand = new RelayCommand(ScanAllAsync, () => HasRoot && !IsScanning);
        CancelCommand = new RelayCommand(() => _cts?.Cancel(), () => IsScanning);
        PrivateInfoCommand = new RelayCommand(OpenPrivateInfoAsync, () => !IsScanning);
        IgnoredCommand = new RelayCommand(OpenIgnoredAsync, () => !IsScanning);
        UndoCommand = new RelayCommand(UndoAsync, () => _undo.Count > 0 && !IsScanning);
        ReportCommand = new RelayCommand(OpenReport, () => Projects.Any(p => p.Result is not null) && !IsScanning);
        FixAllProjectsCommand = new RelayCommand(() => FixAsync(Projects.SelectMany(p => p.MainItems).Where(i => i.CanFix).ToList(), "everything in every project"),
            () => !IsScanning && Projects.Any(p => p.FixableCount > 0));
        FixSelectedCommand = new RelayCommand(() => FixAsync(Projects.SelectMany(p => p.SelectedItems).ToList(), "the selected items"),
            () => !IsScanning && TotalSelected > 0);
        DismissToastCommand = new RelayCommand(() => Toast = "");
    }

    public AppSettings Settings => _settings;
    public ObservableCollection<ProjectViewModel> Projects { get; } = [];
    public string? ScanRoot => _settings.ScanRoot;
    public bool HasRoot => !string.IsNullOrWhiteSpace(_settings.ScanRoot) && Directory.Exists(_settings.ScanRoot);
    public bool ShowWelcome => !HasRoot;
    public bool ShowResults => HasRoot;
    public string ScanRootText => HasRoot ? _settings.ScanRoot! : "No folder chosen yet";
    public double WindowWidth => _settings.WindowWidth;
    public double WindowHeight => _settings.WindowHeight;
    public bool WindowMaximized => _settings.WindowMaximized;

    public bool IsScanning
    {
        get => _isScanning;
        private set
        {
            if (!Set(ref _isScanning, value)) return;
            Raise(nameof(ScanButtonVisible));
            RefreshCommands();
        }
    }

    public bool ScanButtonVisible => !IsScanning;
    public double Progress { get => _progress; private set => Set(ref _progress, value); }
    public string Status { get => _status; private set => Set(ref _status, value); }

    public string Toast
    {
        get => _toast;
        private set { if (Set(ref _toast, value)) Raise(nameof(HasToast)); }
    }

    public bool HasToast => Toast.Length > 0;
    public Avalonia.Media.IBrush ToastBackground => _toastTone switch
    {
        DialogTone.Success => Palette.Success, DialogTone.Warning => Palette.Warning, DialogTone.Danger => Palette.Danger, _ => Palette.Info,
    };
    public Avalonia.Media.IBrush ToastForeground => _toastTone switch
    {
        DialogTone.Success => Palette.SuccessText, DialogTone.Warning => Palette.WarningText, DialogTone.Danger => Palette.DangerText, _ => Palette.InfoText,
    };

    public string GitHubBanner => _tools is { GitInstalled: true, GitHubReady: false }
        ? (_tools.GhInstalled ? "GitHub features are off: the GitHub CLI isn't signed in. Run  gh auth login  in a terminal, then restart Sanitization."
            : "GitHub features are off: the GitHub CLI (gh) isn't installed. Get it from https://cli.github.com, run  gh auth login , then restart Sanitization.")
        : "";
    public bool HasGitHubBanner => GitHubBanner.Length > 0;

    public bool ShowCritical { get => _showCritical; set { if (Set(ref _showCritical, value)) ApplyFilter(); } }
    public bool ShowHigh { get => _showHigh; set { if (Set(ref _showHigh, value)) ApplyFilter(); } }
    public bool ShowMedium { get => _showMedium; set { if (Set(ref _showMedium, value)) ApplyFilter(); } }
    public bool ShowLow { get => _showLow; set { if (Set(ref _showLow, value)) ApplyFilter(); } }

    public int CriticalCount => Projects.Sum(p => p.Critical.Count);
    public int HighCount => Projects.Sum(p => p.High.Count);
    public int MediumCount => Projects.Sum(p => p.Medium.Count);
    public int LowCount => Projects.Sum(p => p.Low.Count);
    public int TotalSelected => Projects.Sum(p => p.SelectedCount);
    public string SelectionText => TotalSelected == 0 ? "Tick items to fix them together, or use a \"Fix all\" button." : $"{TotalSelected} item(s) selected";
    public string FixSelectedText => TotalSelected > 0 ? $"Fix selected ({TotalSelected})" : "Fix selected";
    public string FixAllProjectsText => $"Fix ALL projects ({Projects.Sum(p => p.FixableCount)})";
    public string UndoText => _undo.Count > 0 ? $"Undo last fix ({_undo.Peek().FileCount} file(s))" : "Undo last fix";
    public string ProjectsSummary
    {
        get
        {
            var done = Projects.Count(p => !p.IsScanning);
            var clean = Projects.Count(p => p.IsClean);
            return Projects.Count == 0 ? "" : $"{Projects.Count} projects  ·  {clean} clean  ·  {Projects.Count - clean - (Projects.Count - done)} need attention";
        }
    }

    public RelayCommand ChooseFolderCommand { get; }
    public RelayCommand ScanCommand { get; }
    public RelayCommand CancelCommand { get; }
    public RelayCommand PrivateInfoCommand { get; }
    public RelayCommand IgnoredCommand { get; }
    public RelayCommand UndoCommand { get; }
    public RelayCommand ReportCommand { get; }
    public RelayCommand FixAllProjectsCommand { get; }
    public RelayCommand FixSelectedCommand { get; }
    public RelayCommand DismissToastCommand { get; }

    // ---------------------------------------------------------------- startup

    public async Task StartAsync()
    {
        Status = "Checking tools…";
        _tools = await ToolStatus.ProbeAsync();
        Raise(nameof(GitHubBanner));
        Raise(nameof(HasGitHubBanner));
        if (!_tools.GitInstalled)
        {
            await _ui.ShowDialogAsync(new DialogSpec("Git is required", _tools.GitMissingMessage, DialogTone.Danger, [new DialogButton("Close Sanitization", "Danger")]));
            Environment.Exit(2);
            return;
        }
        _identity = await MachineIdentity.DetectAsync();
        Status = "";
        if (HasRoot) await ScanAllAsync();
    }

    public void SaveWindow(double w, double h, bool maximized)
    {
        _settings.WindowWidth = w;
        _settings.WindowHeight = h;
        _settings.WindowMaximized = maximized;
        try { SettingsStore.Save(_settings); } catch { }
    }

    // ---------------------------------------------------------------- folder + settings

    private async Task ChooseFolderAsync()
    {
        var folder = await _ui.PickFolderAsync();
        if (folder is null) return;
        if (SettingsStore.IsInsideSettings(folder))
        {
            await ShowErrorAsync("Pick another folder", "That folder holds Sanitization's own private settings.");
            return;
        }
        _settings.ScanRoot = folder;
        SettingsStore.Save(_settings);
        foreach (var n in new[] { nameof(ScanRoot), nameof(HasRoot), nameof(ShowWelcome), nameof(ShowResults), nameof(ScanRootText) }) Raise(n);
        RefreshCommands();
        await ScanAllAsync();
    }

    private async Task OpenPrivateInfoAsync()
    {
        await _ui.ShowPrivateInfoAsync(_settings, _identity);
        SettingsStore.Save(_settings);
        if (HasRoot && Projects.Count > 0) await ScanAllAsync();
    }

    private async Task OpenIgnoredAsync()
    {
        if (await _ui.ShowIgnoredAsync(_settings))
        {
            SettingsStore.Save(_settings);
            if (HasRoot) await ScanAllAsync();
        }
    }

    // ---------------------------------------------------------------- scanning

    private Func<Severity, bool> Filter => s => s switch
    {
        Severity.Critical => ShowCritical, Severity.High => ShowHigh, Severity.Medium => ShowMedium, _ => ShowLow,
    };

    private void ApplyFilter()
    {
        foreach (var p in Projects) p.ApplyFilter(Filter);
    }

    public async Task ScanAllAsync()
    {
        if (!HasRoot || IsScanning) return;
        _identity ??= await MachineIdentity.DetectAsync();
        var root = _settings.ScanRoot!;
        Projects.Clear();
        foreach (var info in ProjectDiscovery.Discover(root)) Projects.Add(new ProjectViewModel(info));
        RaiseCounts();
        await ScanProjectsAsync(Projects.ToList());
        var sorted = Projects.OrderBy(p => p.TotalCount == 0 ? 99 : (int)p.AllItems.Min(i => i.Finding.Severity))
            .ThenByDescending(p => p.MainItems.Count()).ThenBy(p => p.Name, StringComparer.OrdinalIgnoreCase).ToList();
        for (var i = 0; i < sorted.Count; i++)
        {
            var at = Projects.IndexOf(sorted[i]);
            if (at != i) Projects.Move(at, i);
        }
        RaiseCounts();
    }

    public async Task RescanProjectsAsync(IReadOnlyList<ProjectViewModel> projects)
    {
        if (IsScanning) return;
        foreach (var p in projects) p.IsScanning = true;
        await ScanProjectsAsync(projects);
        RaiseCounts();
    }

    private async Task ScanProjectsAsync(IReadOnlyList<ProjectViewModel> list)
    {
        IsScanning = true;
        _cts = new CancellationTokenSource();
        var ct = _cts.Token;
        var sw = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            for (var i = 0; i < list.Count; i++)
            {
                var vm = list[i];
                vm.IsScanning = true;
                vm.Status = "Scanning…";
                var index = i;
                var progress = new Progress<(string Phase, int Done, int Total)>(p =>
                {
                    var phaseShare = p.Phase == "Files" ? 0.0 : 0.5;
                    var frac = p.Total == 0 ? 0 : (double)p.Done / p.Total;
                    Progress = (index + phaseShare + frac * 0.5) / list.Count * 100;
                    var what = p.Phase == "Files" ? "files" : "git history";
                    Status = $"Scanning {vm.Name}  —  {what} {p.Done:N0} / {p.Total:N0}";
                    vm.Status = $"Scanning {what}… {p.Done:N0} / {p.Total:N0}";
                });
                Status = $"Scanning {vm.Name}…";
                Progress = (double)index / list.Count * 100;
                try
                {
                    var info = vm.Info;
                    var fresh = new ProjectInfo { Name = info.Name, Path = info.Path, IsGit = Git.IsRepo(info.Path), TopLevelOnly = info.TopLevelOnly };
                    var result = await Task.Run(() => Scanner.ScanAsync(fresh, _identity!, _settings.PrivateTerms, _settings.IgnoredFor(info.Path), progress, ct), ct);
                    vm.Load(result, Filter);
                    _ = FetchVisibilityAsync(vm);
                }
                catch (OperationCanceledException) { vm.IsScanning = false; vm.Status = "Cancelled"; throw; }
                catch (Exception e)
                {
                    vm.Load(new ProjectScanResult { Project = vm.Info, Findings = [] }, Filter);
                    vm.Banners.Add(new BannerViewModel("This project could not be scanned: " + e.Message, Palette.Danger, Palette.DangerText));
                }
                RaiseCounts();
            }
            Progress = 100;
            Status = $"Scan finished in {sw.Elapsed.TotalSeconds:0}s  ·  {CriticalCount} critical, {HighCount} high, {MediumCount} medium, {LowCount} probably fine";
        }
        catch (OperationCanceledException)
        {
            foreach (var p in list.Where(p => p.IsScanning)) { p.IsScanning = false; p.Status = "Not scanned (cancelled)"; }
            Status = "Scan cancelled.";
        }
        finally
        {
            IsScanning = false;
            _cts.Dispose();
            _cts = null;
        }
    }

    private async Task FetchVisibilityAsync(ProjectViewModel vm)
    {
        if (vm.Info.GitHub is null || _tools is not { GitHubReady: true }) return;
        var info = await GitHubService.GetRepoAsync(vm.Info.GitHub);
        if (info.Exists) Dispatcher.UIThread.Post(() => vm.Visibility = info.Visibility);
    }

    private void RaiseCounts()
    {
        foreach (var n in new[] { nameof(CriticalCount), nameof(HighCount), nameof(MediumCount), nameof(LowCount), nameof(ProjectsSummary),
                     nameof(FixAllProjectsText), nameof(UndoText) })
            Raise(n);
        OnSelectionChanged();
        RefreshCommands();
    }

    public void OnSelectionChanged()
    {
        Raise(nameof(TotalSelected));
        Raise(nameof(SelectionText));
        Raise(nameof(FixSelectedText));
        FixSelectedCommand.Refresh();
    }

    private void RefreshCommands()
    {
        foreach (var c in new[] { ChooseFolderCommand, ScanCommand, CancelCommand, PrivateInfoCommand, IgnoredCommand, UndoCommand, ReportCommand, FixAllProjectsCommand, FixSelectedCommand })
            c.Refresh();
        foreach (var p in Projects)
        {
            p.FixAllCommand.Refresh();
            p.FixSelectedCommand.Refresh();
            p.PushCommand.Refresh();
            p.RescanCommand.Refresh();
        }
    }

    // ---------------------------------------------------------------- fixing

    public async Task FixAsync(IReadOnlyList<FindingViewModel> items, string what)
    {
        var fixable = items.Where(i => i.CanFix).ToList();
        if (fixable.Count == 0)
        {
            ShowToast("Nothing here can be fixed automatically.", DialogTone.Info);
            return;
        }
        var byProject = fixable.GroupBy(i => i.Project).ToList();
        var historyProjects = byProject.Where(g => g.Any(i => FixPlanner.TouchesHistory(i.Finding))).ToList();
        var allowHistory = true;
        if (historyProjects.Count > 0)
        {
            var bullets = historyProjects.Select(g => g.Key.Info.HasUncommittedChanges
                ? $"{g.Key.Name}: has uncommitted changes, so its history will be SKIPPED (files are still fixed). Commit or stash first, then fix again."
                : $"{g.Key.Name}: {g.Key.Info.LocalCommits} commit(s) will be rewritten.").ToList();
            var choice = await _ui.ShowDialogAsync(new DialogSpec(
                "This rewrites git history and can't be undone",
                $"Fixing {what} removes values from old commits too. Every commit hash changes. No backup is kept.",
                DialogTone.Danger,
                [new DialogButton("Rewrite history and fix", "Danger"), new DialogButton("Fix files only"), new DialogButton("Cancel", IsCancel: true)],
                bullets,
                "Afterwards, push to GitHub so it gets the cleaned history too. Anyone with a copy of the repo will need to re-clone it."));
            if (choice == 2 || choice < 0) return;
            allowHistory = choice == 0;
        }

        IsScanning = true;
        var undo = new UndoBatch { Summary = what };
        var outcomes = new List<FixOutcome>();
        try
        {
            foreach (var g in byProject)
            {
                Status = $"Fixing {g.Key.Name}…";
                g.Key.Status = "Fixing…";
                var progress = new Progress<string>(s => { Status = $"{g.Key.Name}: {s}"; g.Key.Status = s; });
                var findings = g.Select(i => i.Finding).ToList();
                outcomes.Add(await Task.Run(() => Fixer.ApplyAsync(g.Key.Info, findings, allowHistory, undo, progress, CancellationToken.None)));
            }
        }
        finally
        {
            IsScanning = false;
        }
        if (!undo.IsEmpty) _undo.Push(undo);
        Raise(nameof(UndoText));

        var before = fixable.Count;
        await RescanProjectsAsync(byProject.Select(g => g.Key).ToList());
        var stillThere = byProject.Sum(g => g.Key.AllItems.Count(i => fixable.Any(f => f.Finding.Key == i.Finding.Key && !i.Finding.OnlyOnRemote)));
        var errors = outcomes.SelectMany(o => o.Errors.Select(e => $"{o.Project.Name}: {e}")).ToList();
        var blocked = outcomes.Where(o => o.HistoryBlocked is not null).Select(o => $"{o.Project.Name}: history not cleaned. {o.HistoryBlocked}").ToList();
        var rewritten = outcomes.Where(o => o.HistoryRewritten).Select(o => o.Project.Name).ToList();
        var needPush = byProject.Where(g => g.Key.CanPush && g.Key.HighlightPush).Select(g => $"{g.Key.Name} (\"{g.Key.PushText}\")").ToList();

        if (errors.Count > 0 || blocked.Count > 0)
        {
            var bullets = errors.Concat(blocked).ToList();
            await _ui.ShowDialogAsync(new DialogSpec(errors.Count > 0 ? "Some fixes didn't work" : "Partly done",
                $"Fixed {before - stillThere} of {before} item(s). Checked again by re-scanning.", errors.Count > 0 ? DialogTone.Danger : DialogTone.Warning,
                [new DialogButton("OK", "Primary")], bullets));
        }
        else
        {
            var msg = $"Fixed {before - stillThere} of {before} item(s). Checked again by re-scanning: {(stillThere == 0 ? "all gone" : $"{stillThere} still found")}.";
            if (rewritten.Count > 0) msg += $"  History cleaned in {string.Join(", ", rewritten)}.";
            if (needPush.Count > 0) msg += $"  Next step: push {string.Join(", ", needPush)}.";
            ShowToast(msg, stillThere == 0 ? DialogTone.Success : DialogTone.Warning);
        }
    }

    private async Task UndoAsync()
    {
        if (_undo.Count == 0) return;
        var batch = _undo.Pop();
        var problems = await Fixer.UndoAsync(batch);
        Raise(nameof(UndoText));
        UndoCommand.Refresh();
        if (problems.Count > 0)
            await _ui.ShowDialogAsync(new DialogSpec("Undo was partial", "Some files were not restored:", DialogTone.Warning, [new DialogButton("OK", "Primary")], problems));
        else ShowToast($"Undone: {batch.Summary} ({batch.FileCount} file(s) restored). History changes can't be undone.", DialogTone.Info);
        var touched = batch.Paths.ToList();
        await RescanProjectsAsync(Projects.Where(p => touched.Any(t => t.StartsWith(p.Info.Path.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase)
                                                                      || t.Equals(p.Info.Path, StringComparison.OrdinalIgnoreCase))).ToList());
    }

    public async Task IgnoreAsync(FindingViewModel vm)
    {
        _settings.Ignore(vm.Finding.ProjectPath, vm.Finding.Value);
        SettingsStore.Save(_settings);
        vm.Project.Remove(vm);
        RaiseCounts();
        ShowToast($"Marked as not a problem in {vm.Project.Name}. Undo it from \"Ignored items\".", DialogTone.Info);
        await Task.CompletedTask;
    }

    // ---------------------------------------------------------------- pushing

    private async Task<bool> RequireGitHubAsync()
    {
        _tools = await ToolStatus.ProbeAsync();
        Raise(nameof(GitHubBanner));
        Raise(nameof(HasGitHubBanner));
        if (_tools.GitHubReady) return true;
        await _ui.ShowDialogAsync(new DialogSpec("GitHub CLI needed", _tools.GitHubMissingMessage, DialogTone.Danger, [new DialogButton("OK", "Primary")]));
        return false;
    }

    public async Task PushAsync(ProjectViewModel p)
    {
        if (p.Info.GitHub is not null && !await RequireGitHubAsync()) return;
        var oldOnRemote = p.Info.RemoteOnlyCommits > 0 || p.AllItems.Any(i => i.Finding.OnRemote);
        var target = p.Info.GitHub?.FullName ?? p.Info.OriginUrl ?? "origin";
        List<DialogButton> buttons = [new DialogButton("Force-push now", "Danger")];
        if (oldOnRemote && p.Info.GitHub is not null) buttons.Add(new DialogButton("Delete & recreate the repo (complete)", "Primary"));
        buttons.Add(new DialogButton("Cancel", IsCancel: true));
        var bullets = new List<string>
        {
            "Replaces the history on " + target + " with your cleaned history: all branches and tags.",
            "Anyone who already has a copy must re-clone it.",
        };
        if (oldOnRemote)
            bullets.Add("Heads up: GitHub can keep the OLD commits reachable through a direct link, forks and pull requests even after a force-push. To remove them completely, delete and recreate the repository (the guide walks you through it).");
        var choice = await _ui.ShowDialogAsync(new DialogSpec($"Push {p.Name}?", $"Push to {target}", oldOnRemote ? DialogTone.Warning : DialogTone.Info, buttons, bullets));
        if (choice < 0 || buttons[choice].IsCancel) return;
        if (buttons[choice].Text.StartsWith("Delete", StringComparison.Ordinal))
        {
            if (await _ui.ShowRecreateWizardAsync(p)) await RescanProjectsAsync([p]);
            return;
        }
        IsScanning = true;
        Status = $"Pushing {p.Name}…";
        (bool Ok, string Log) result;
        try { result = await Task.Run(() => GitHubService.ForcePushAsync(p.Info.Path, lease: true)); }
        finally { IsScanning = false; }
        if (!result.Ok)
        {
            await _ui.ShowDialogAsync(new DialogSpec("Push failed", "Git said:", DialogTone.Danger, [new DialogButton("OK", "Primary")],
                [result.Log.Trim(), "If the remote changed since your last fetch, run \"git fetch\" in that repo, check what changed, then push again."]));
            return;
        }
        var stale = await GitHubService.StaleRemoteBranchesAsync(p.Info.Path);
        await RescanProjectsAsync([p]);
        if (stale.Count > 0)
        {
            var c = await _ui.ShowDialogAsync(new DialogSpec("Old branches still on the remote",
                "These remote branches don't exist locally, so the push didn't replace them. They still hold the old history:",
                DialogTone.Warning, [new DialogButton("Open the delete & recreate guide", "Primary"), new DialogButton("Close", IsCancel: true)], stale,
                "Delete them on GitHub (Branches page), or recreate the repo for a complete clean-up."));
            if (c == 0 && p.Info.GitHub is not null && await _ui.ShowRecreateWizardAsync(p)) await RescanProjectsAsync([p]);
        }
        else ShowToast($"{p.Name} pushed. {target} now has the cleaned history.", DialogTone.Success);
    }

    // ---------------------------------------------------------------- report + helpers

    private void OpenReport()
    {
        var results = Projects.Where(p => p.Result is not null).Select(p => new ProjectScanResult
        {
            Project = p.Info, Findings = p.AllItems.Select(i => i.Finding).ToList(),
        }).ToList();
        var html = Report.BuildHtml(_settings.ScanRoot ?? "", results, DateTime.Now);
        Report.OpenInBrowser(Report.ServeOnce(html));
        ShowToast("Report opened in your browser. It isn't saved anywhere: closing the tab deletes it.", DialogTone.Info);
    }

    public void ShowToast(string text, DialogTone tone)
    {
        _toastTone = tone;
        Raise(nameof(ToastBackground));
        Raise(nameof(ToastForeground));
        Toast = text;
        var id = ++_toastId;
        DispatcherTimer.RunOnce(() => { if (id == _toastId) Toast = ""; }, TimeSpan.FromSeconds(12));
    }

    public Task ShowErrorAsync(string title, string message) =>
        _ui.ShowDialogAsync(new DialogSpec(title, message, DialogTone.Danger, [new DialogButton("OK", "Primary")]));
}
