namespace TechFix.WebApi.Controllers;

using Microsoft.AspNetCore.Mvc;
using TechFix.Application.DTOs;
using TechFix.Application.Interfaces;

[ApiController]
[Route("api/[controller]")]
[Tags("OWASP A10: Insufficient Logging and Monitoring")]
[Produces("application/json")]
public class A10_LoggingMonitoringController : ControllerBase
{
    private readonly ILoggingMonitoringService _loggingService;

    public A10_LoggingMonitoringController(ILoggingMonitoringService loggingService)
    {
        _loggingService = loggingService;
    }

    // ==========================================================
    // 1. LOG INJECTION / CRLF LOG POISONING (CWE-117)
    // ==========================================================

    /// <summary>
    /// Вразливе логування: несанкціоноване впровадження символів переведення рядка (CRLF) для фальсифікації журналів.
    /// </summary>
    [HttpPost("log-injection/vulnerable")]
    [ProducesResponseType(typeof(LogInjectionResultDto), StatusCodes.Status200OK)]
    public async Task<IActionResult> LogInjectionVulnerable([FromBody] LogInjectionRequestDto request)
    {
        var result = await _loggingService.ProcessLogInjectionVulnerableAsync(request);
        return Ok(result);
    }

    /// <summary>
    /// Захищене логування: санітизація CRLF символів та використання структурованої телеметрії JSON.
    /// </summary>
    [HttpPost("log-injection/secure")]
    [ProducesResponseType(typeof(LogInjectionResultDto), StatusCodes.Status200OK)]
    public async Task<IActionResult> LogInjectionSecure([FromBody] LogInjectionRequestDto request)
    {
        var result = await _loggingService.ProcessLogInjectionSecureAsync(request);
        return Ok(result);
    }

    // ==========================================================
    // 2. AUDIT TRAIL COMPLETENESS (CWE-778)
    // ==========================================================

    /// <summary>
    /// Вразлива фінансова дія: проведення повернення коштів без запису в журнал аудиту (Silent Operation).
    /// </summary>
    [HttpPost("financial-action/vulnerable")]
    [ProducesResponseType(typeof(FinancialActionResultDto), StatusCodes.Status200OK)]
    public async Task<IActionResult> FinancialActionVulnerable([FromBody] FinancialActionRequestDto request)
    {
        var result = await _loggingService.ProcessFinancialActionVulnerableAsync(request);
        return Ok(result);
    }

    /// <summary>
    /// Захищена фінансова дія: автоматична фіксація незмінного запису в журналі аудиту з CorrelationId та IP.
    /// </summary>
    [HttpPost("financial-action/secure")]
    [ProducesResponseType(typeof(FinancialActionResultDto), StatusCodes.Status200OK)]
    public async Task<IActionResult> FinancialActionSecure([FromBody] FinancialActionRequestDto request)
    {
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "192.168.1.55";
        var result = await _loggingService.ProcessFinancialActionSecureAsync(request, ip);
        return Ok(result);
    }

    // ==========================================================
    // 3. ANOMALY DETECTION & REAL-TIME ALERTING (CWE-392)
    // ==========================================================

    /// <summary>
    /// Вразливий моніторинг авторизації: відсутність сповіщень при багаторазових невдалих спробах входу.
    /// </summary>
    [HttpPost("login-probe/vulnerable")]
    [ProducesResponseType(typeof(LoginProbeResultDto), StatusCodes.Status200OK)]
    public async Task<IActionResult> LoginProbeVulnerable([FromBody] LoginProbeRequestDto request)
    {
        var result = await _loggingService.ProcessLoginProbeVulnerableAsync(request);
        return Ok(result);
    }

    /// <summary>
    /// Захищений моніторинг авторизації: автоматична генерація інциденту безпеки та сповіщення SIEM при 3+ невдалих спробах.
    /// </summary>
    [HttpPost("login-probe/secure")]
    [ProducesResponseType(typeof(LoginProbeResultDto), StatusCodes.Status200OK)]
    public async Task<IActionResult> LoginProbeSecure([FromBody] LoginProbeRequestDto request)
    {
        var result = await _loggingService.ProcessLoginProbeSecureAsync(request);
        return Ok(result);
    }

    // ==========================================================
    // 4. SECURITY AUDIT LOG QUERY
    // ==========================================================

    /// <summary>
    /// Отримання останніх подій журналу аудиту безпеки для аналізу інцидентів.
    /// </summary>
    [HttpGet("audit-events")]
    [ProducesResponseType(typeof(IReadOnlyList<SecurityAuditEventDto>), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetAuditEvents()
    {
        var list = await _loggingService.GetRecentAuditEventsAsync();
        return Ok(list);
    }
}
