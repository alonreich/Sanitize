namespace Sanitization.Core;

public enum Severity { Critical = 0, High = 1, Medium = 2, Low = 3 }

public enum FindingKind
{
    TextValue,
    WholeFile,
    CommitIdentity,
    RemoteUrl,
}

public enum FileState { None, Tracked, Untracked, Ignored, NotGit }

[Flags]
public enum FixActions
{
    None = 0,
    ReplaceInFile = 1,
    RewriteHistory = 2,
    DropFromHistory = 4,
    Untrack = 8,
    AddToGitignore = 16,
    RewriteIdentity = 32,
    CleanRemoteUrl = 64,
    PushToFinish = 128,
    StripPhotoGps = 256,
    StripPhotoGpsInHistory = 512,
}

public sealed class Finding
{
    public required string ProjectPath { get; init; }
    public required FindingKind Kind { get; init; }
    public required Severity Severity { get; set; }
    public required string Category { get; init; }
    public required string Why { get; init; }
    public required string Value { get; init; }
    public string? SuggestedReplacement { get; init; }
    public string? Replacement { get; set; }
    public string RelativePath { get; init; } = "";
    public FileState FileState { get; set; }
    public List<int> Lines { get; } = [];
    public string? Snippet { get; set; }
    public bool InWorkingTree { get; set; }
    public bool InLocalHistory { get; set; }
    public bool OnRemote { get; set; }
    public int HistoryVersions { get; set; }
    public HashSet<string> CommitMessages { get; } = new(StringComparer.Ordinal);
    public bool Inspectable { get; init; } = true;
    public bool PhotoGps { get; init; }
    public bool InsideDocument { get; init; }
    public bool Propagated { get; set; }
    public string? RemoteName { get; init; }

    public string Key => $"{(int)Kind}|{RelativePath}|{Value}";

    public string Id => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
        System.Text.Encoding.UTF8.GetBytes(ProjectPath.ToLowerInvariant() + "|" + Key)))[..8].ToLowerInvariant();
    public FixActions Actions { get; set; }
    public bool CanFix => (Actions & ~FixActions.PushToFinish) != FixActions.None;
    public bool OnlyOnRemote => Actions == FixActions.PushToFinish;
    public string FixDescription { get; set; } = "";
    public string? NoFixReason { get; set; }
}

public sealed record GitHubRepoRef(string Owner, string Name)
{
    public string FullName => $"{Owner}/{Name}";
    public string Url => $"https://github.com/{Owner}/{Name}";
}

public sealed class ProjectInfo
{
    public required string Name { get; init; }
    public required string Path { get; init; }
    public bool IsGit { get; set; }
    public bool TopLevelOnly { get; init; }
    public bool HasUncommittedChanges { get; set; }
    public string? Branch { get; set; }
    public string? OriginUrl { get; set; }
    public GitHubRepoRef? GitHub { get; set; }
    public int LocalCommits { get; set; }
    public int RemoteOnlyCommits { get; set; }
    public int LocalOnlyCommits { get; set; }
    public bool NeedsForcePush => RemoteOnlyCommits > 0 && LocalOnlyCommits > 0;
    public List<string> Notes { get; } = [];
    public int FilesScanned { get; set; }
    public int BlobsScanned { get; set; }
}

public sealed class ProjectScanResult
{
    public required ProjectInfo Project { get; init; }
    public required List<Finding> Findings { get; init; }
    public TimeSpan Duration { get; init; }
}

public sealed record ScanProgress(string ProjectName, int ProjectIndex, int ProjectCount, string Phase, int Done, int Total);

public sealed class PrivateTerm
{
    public string Value { get; set; } = "";
    public string Replacement { get; set; } = "REDACTED";
}
