using System.Text;
using Sanitization.Core;

Console.OutputEncoding = new UTF8Encoding(false);
var dir = Environment.GetEnvironmentVariable("SANITIZATION_SETTINGS_DIR");
if (!string.IsNullOrWhiteSpace(dir)) SettingsStore.Directory_ = dir;
using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
return await CliApp.RunAsync(args, Console.Out, Console.Error, cts.Token);
