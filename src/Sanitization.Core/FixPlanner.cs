namespace Sanitization.Core;

public static class FixPlanner
{
    public static void Plan(ProjectInfo p, Finding f)
    {
        var a = FixActions.None;
        string? noFix = null;
        var remoteWord = p.GitHub is not null ? "GitHub" : "the remote";
        switch (f.Kind)
        {
            case FindingKind.TextValue:
                if (f.InsideDocument)
                {
                    noFix = "Inside an Office document. Open it in Word / Excel / PowerPoint and edit it there (File > Info > Inspect Document removes author data).";
                    break;
                }
                if (f.InWorkingTree) a |= FixActions.ReplaceInFile;
                if (f.InLocalHistory) a |= FixActions.RewriteHistory;
                if (a == FixActions.None && f.OnRemote) a = FixActions.PushToFinish;
                break;
            case FindingKind.WholeFile:
                if (f.PhotoGps)
                {
                    if (f.InWorkingTree) a |= FixActions.StripPhotoGps;
                    if (f.InLocalHistory && p.IsGit) a |= FixActions.StripPhotoGpsInHistory;
                    if (a == FixActions.None && f.OnRemote) a = FixActions.PushToFinish;
                    break;
                }
                if (!f.Inspectable) { noFix = "Can't be fixed automatically. Open it, check it, then fix or ignore it."; break; }
                if (!p.IsGit) { noFix = "Not in git. Delete or move this file yourself before you share the folder."; break; }
                if (f.InWorkingTree && f.FileState == FileState.Tracked) a |= FixActions.Untrack | FixActions.AddToGitignore;
                if (f.InWorkingTree && f.FileState == FileState.Untracked) a |= FixActions.AddToGitignore;
                if (f.InLocalHistory) a |= FixActions.DropFromHistory;
                if (a == FixActions.None && f.OnRemote) a = FixActions.PushToFinish;
                if (a == FixActions.None && f.FileState == FileState.Ignored)
                    noFix = "Already ignored by git, so it never reaches GitHub. Delete it yourself before you zip or share the folder.";
                break;
            case FindingKind.CommitIdentity:
                if (f.InLocalHistory) a |= FixActions.RewriteIdentity;
                else if (f.OnRemote) a = FixActions.PushToFinish;
                break;
            case FindingKind.RemoteUrl:
                a |= FixActions.CleanRemoteUrl;
                break;
        }
        f.Actions = a;
        f.NoFixReason = noFix;
        f.FixDescription = Describe(a, f, remoteWord) ?? noFix ?? "";
    }

    private static string? Describe(FixActions a, Finding f, string remoteWord)
    {
        if (a == FixActions.None) return null;
        if (a == FixActions.PushToFinish) return $"Already removed here. Push to {remoteWord} to finish.";
        var parts = new List<string>();
        if (a.HasFlag(FixActions.ReplaceInFile)) parts.Add(f.FileState == FileState.Ignored ? "replace in the local file" : "replace in the file");
        if (a.HasFlag(FixActions.RewriteHistory)) parts.Add("remove from git history");
        if (a.HasFlag(FixActions.Untrack)) parts.Add("stop tracking it (file stays on disk)");
        if (a.HasFlag(FixActions.AddToGitignore)) parts.Add("add to .gitignore");
        if (a.HasFlag(FixActions.DropFromHistory)) parts.Add("remove the file from git history");
        if (a.HasFlag(FixActions.RewriteIdentity)) parts.Add(f.Value.Contains('@') ? "change the author e-mail in all commits" : "change the author name in all commits");
        if (a.HasFlag(FixActions.StripPhotoGps)) parts.Add("remove the location / camera data from the photo (the picture itself is unchanged)");
        if (a.HasFlag(FixActions.StripPhotoGpsInHistory)) parts.Add("strip it from every old version in git history");
        if (a.HasFlag(FixActions.CleanRemoteUrl)) parts.Add("remove the password from the remote URL");
        var s = string.Join(", ", parts);
        return char.ToUpperInvariant(s[0]) + s[1..] + ".";
    }

    public static bool TouchesHistory(Finding f) => (f.Actions & (FixActions.RewriteHistory | FixActions.DropFromHistory | FixActions.RewriteIdentity | FixActions.StripPhotoGpsInHistory)) != 0;
}
