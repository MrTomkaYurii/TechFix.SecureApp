namespace TechFix.WebApi.Controllers;

using Microsoft.AspNetCore.Mvc;
using TechFix.Application.DTOs;
using TechFix.Application.Interfaces;

[ApiController]
[Route("api/[controller]")]
[Tags("OWASP A9: Using Components with Known Vulnerabilities")]
[Produces("application/json")]
public class A9_VulnerableComponentsController : ControllerBase
{
    private readonly IComponentSecurityService _componentSecurityService;

    public A9_VulnerableComponentsController(IComponentSecurityService componentSecurityService)
    {
        _componentSecurityService = componentSecurityService;
    }

    // ==========================================================
    // 1. VULNERABILITY SCANNING (CWE-1104 / CWE-1035)
    // ==========================================================

    /// <summary>
    /// Вразливий аудит компонентів: сканування застарілих залежностей із критичними CVE (Nikto / OpenVAS).
    /// </summary>
    [HttpGet("audit/vulnerable")]
    [ProducesResponseType(typeof(DependencyScanReportDto), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetAuditVulnerable()
    {
        var result = await _componentSecurityService.ScanDependenciesVulnerableAsync();
        return Ok(result);
    }

    /// <summary>
    /// Захищений аудит компонентів: сканування сучасного стека .NET 10 (0 відомих вразливостей, повна відповідність).
    /// </summary>
    [HttpGet("audit/secure")]
    [ProducesResponseType(typeof(DependencyScanReportDto), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetAuditSecure()
    {
        var result = await _componentSecurityService.ScanDependenciesSecureAsync();
        return Ok(result);
    }

    // ==========================================================
    // 2. SOFTWARE BILL OF MATERIALS (SBOM)
    // ==========================================================

    /// <summary>
    /// Генерація паспорта програмного забезпечення (SBOM) у форматі стандарту CycloneDX v1.5.
    /// </summary>
    [HttpGet("sbom")]
    [ProducesResponseType(typeof(SbomReportDto), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetSbom()
    {
        var result = await _componentSecurityService.GenerateSbomSecureAsync();
        return Ok(result);
    }

    // ==========================================================
    // 3. REMEDIATION ROADMAP & CI/CD ENFORCEMENT
    // ==========================================================

    /// <summary>
    /// Дорожня карта усунення вразливостей та автоматизовані команди оновлення dotnet CLI.
    /// </summary>
    [HttpGet("remediation-plan")]
    [ProducesResponseType(typeof(ComponentRemediationPlanDto), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetRemediationPlan()
    {
        var result = await _componentSecurityService.GetRemediationPlanAsync();
        return Ok(result);
    }
}
