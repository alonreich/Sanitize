using Avalonia.Controls;
using Avalonia.Markup.Xaml;
using Avalonia.Platform.Storage;
using Sanitization.Core;

namespace Sanitization.App;

public sealed partial class MainWindow : Window, IUi
{
    private readonly MainViewModel _vm;

    public MainWindow()
    {
        AvaloniaXamlLoader.Load(this);
        _vm = new MainViewModel(this);
        DataContext = _vm;
        if (_vm.WindowWidth >= MinWidth && _vm.WindowHeight >= MinHeight)
        {
            Width = _vm.WindowWidth;
            Height = _vm.WindowHeight;
        }
        if (_vm.WindowMaximized) WindowState = WindowState.Maximized;
        Opened += async (_, _) => await _vm.StartAsync();
        Closing += (_, _) => _vm.SaveWindow(Bounds.Width, Bounds.Height, WindowState == WindowState.Maximized);
    }

    public Task<int> ShowDialogAsync(DialogSpec spec) => new MessageDialog(spec).ShowDialog<int>(this);

    public async Task<string?> PickFolderAsync()
    {
        var folders = await StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
        {
            Title = "Choose the folder that holds all your projects",
            AllowMultiple = false,
        });
        return folders.Count > 0 ? folders[0].TryGetLocalPath() : null;
    }

    public Task ShowPrivateInfoAsync(AppSettings settings, MachineIdentity? id) => new PrivateInfoWindow(settings, id).ShowDialog(this);

    public Task<bool> ShowIgnoredAsync(AppSettings settings) => new IgnoredItemsWindow(settings).ShowDialog<bool>(this);

    public Task<bool> ShowRecreateWizardAsync(ProjectViewModel project) => new RecreateWizard(project.Info).ShowDialog<bool>(this);
}
