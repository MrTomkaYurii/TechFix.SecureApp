namespace TechFix.Application.DTOs;

public class DependencyAuditItemDto
{
    public string PackageName { get; set; } = string.Empty;
    public string InstalledVersion { get; set; } = string.Empty;
    public string FixedVersion { get; set; } = string.Empty;
    public string CveId { get; set; } = string.Empty;
    public double CvssScore { get; set; }
    public string Severity { get; set; } = "Low";
    public string Description { get; set; } = string.Empty;
    public string RemediationAction { get; set; } = string.Empty;
}

public class DependencyScanReportDto
{
    public string ProjectName { get; set; } = "TechFix.SecureApp";
    public string Framework { get; set; } = ".NET 10.0";
    public int TotalDependencies { get; set; }
    public int VulnerableDependenciesCount { get; set; }
    public DateTime ScanTimestamp { get; set; }
    public bool IsCompliant { get; set; }
    public string ScanTool { get; set; } = "dotnet-audit / OpenVAS / Nikto";
    public List<DependencyAuditItemDto> Items { get; set; } = new();
}

public class SbomComponentDto
{
    public string Name { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public string Purl { get; set; } = string.Empty;
    public string License { get; set; } = "MIT / Apache-2.0";
    public string IntegrityHash { get; set; } = string.Empty;
}

public class SbomReportDto
{
    public string BomFormat { get; set; } = "CycloneDX";
    public string SpecVersion { get; set; } = "1.5";
    public string SerialNumber { get; set; } = string.Empty;
    public int Version { get; set; } = 1;
    public DateTime Timestamp { get; set; }
    public string TargetComponent { get; set; } = "TechFix.Enterprise.Platform";
    public List<SbomComponentDto> Components { get; set; } = new();
}

public class ComponentRemediationPlanDto
{
    public string Strategy { get; set; } = "Automated Vulnerability Remediation & CI/CD Gate";
    public List<string> CliUpgradeCommands { get; set; } = new();
    public List<string> PolicyEnforcements { get; set; } = new();
}
