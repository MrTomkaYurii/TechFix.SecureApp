namespace TechFix.Application.Interfaces;
using TechFix.Application.DTOs;

public interface IComponentSecurityService
{
    // Task 1 & 2: Vulnerability Scanner Audits (Nikto / OpenVAS / dotnet-audit)
    Task<DependencyScanReportDto> ScanDependenciesVulnerableAsync();
    Task<DependencyScanReportDto> ScanDependenciesSecureAsync();

    // Task 3: Software Bill of Materials (SBOM) & Remediation Roadmap
    Task<SbomReportDto> GenerateSbomSecureAsync();
    Task<ComponentRemediationPlanDto> GetRemediationPlanAsync();
}
