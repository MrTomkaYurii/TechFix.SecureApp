using Microsoft.AspNetCore.Mvc;
using TechFix.Application.Interfaces;

namespace TechFix.WebApi.Controllers;

[ApiController]
[Route("api/[controller]")]
[Tags("OWASP A6: Security Misconfiguration")]
public class A6_SecurityMisconfigController : ControllerBase
{
    private readonly ISecurityMisconfigService _misconfigService;

    public A6_SecurityMisconfigController(ISecurityMisconfigService misconfigService)
    {
        _misconfigService = misconfigService;
    }

    // ==========================================================
    // 1. UNHANDLED ERROR & STACK TRACE LEAKS
    // ==========================================================

    /// <summary>
    /// Вразлива обробка помилок: викидає сирий виняток зі стеком викликів та рядком підключення до БД (CWE-209).
    /// </summary>
    [HttpGet("error-handling/vulnerable")]
    public async Task<IActionResult> ErrorHandlingVulnerable([FromQuery] string trigger = "sql_fail")
    {
        try
        {
            var result = await _misconfigService.TriggerErrorVulnerableAsync(trigger);
            return Ok(result);
        }
        catch (Exception ex)
        {
            // АНТИПАТЕРН: Повернення повного стеку викликів та системних шляхів у відповідь клієнту
            return StatusCode(500, new
            {
                Error = ex.Message,
                ExceptionType = ex.GetType().FullName,
                StackTrace = ex.StackTrace,
                ServerTime = DateTime.UtcNow,
                DebugMode = "Enabled (Production Security Misconfiguration)"
            });
        }
    }

    /// <summary>
    /// Захищена обробка помилок: повертає стандартизований RFC 7807 ProblemDetails із унікальним Trace ID без витоку стеку.
    /// </summary>
    [HttpGet("error-handling/secure")]
    public async Task<IActionResult> ErrorHandlingSecure([FromQuery] string trigger = "sql_fail")
    {
        var result = await _misconfigService.TriggerErrorSecureAsync(trigger);
        return StatusCode(500, result);
    }

    // ==========================================================
    // 2. EXPOSED SENSITIVE & BACKUP FILES
    // ==========================================

    /// <summary>
    /// Вразливий доступ: дозволяє пряме завантаження файлів резервних копій та баз даних (.bak, .kdbx).
    /// </summary>
    [HttpGet("backup-files/vulnerable")]
    public async Task<IActionResult> BackupFilesVulnerable([FromQuery] string fileName = "techfix_backup_2026.bak")
    {
        var result = await _misconfigService.AccessBackupFileVulnerableAsync(fileName);
        return Ok(result);
    }

    /// <summary>
    /// Захищений доступ: блокує будь-які запити до службових та резервних файлів (403 Forbidden).
    /// </summary>
    [HttpGet("backup-files/secure")]
    public async Task<IActionResult> BackupFilesSecure([FromQuery] string fileName = "techfix_backup_2026.bak")
    {
        var result = await _misconfigService.AccessBackupFileSecureAsync(fileName);
        if (!result.Success) return StatusCode(403, result);
        return Ok(result);
    }

    // ==========================================================
    // 3. DEVELOPER COMMENTS & CREDENTIALS LEAK
    // ==========================================================

    /// <summary>
    /// Вразливі клієнтські скрипти: містять залишені коментарі розробників з паролями служби підтримки (CWE-615).
    /// </summary>
    [HttpGet("support-secrets/vulnerable")]
    public async Task<IActionResult> SupportSecretsVulnerable()
    {
        var result = await _misconfigService.GetSupportCredentialsLeakVulnerableAsync();
        return Ok(result);
    }

    /// <summary>
    /// Захищені клієнтські скрипти: мініфіковані та очищені через автоматизований CI/CD конвеєр.
    /// </summary>
    [HttpGet("support-secrets/secure")]
    public async Task<IActionResult> SupportSecretsSecure()
    {
        var result = await _misconfigService.GetSupportCredentialsLeakSecureAsync();
        return Ok(result);
    }

    // ==========================================================
    // 4. SECURITY HEADERS AUDIT
    // ==========================================================

    /// <summary>
    /// Аудит заголовків уразливого сервера: розкриття Server, X-Powered-By, відсутність CSP та X-Frame-Options.
    /// </summary>
    [HttpGet("headers-audit/vulnerable")]
    public IActionResult HeadersAuditVulnerable()
    {
        var result = _misconfigService.AuditSecurityHeaders(secureMode: false);
        return Ok(result);
    }

    /// <summary>
    /// Аудит захищеної конфігурації: суворі заголовки безпеки (HSTS, CSP, nosniff, DENY).
    /// </summary>
    [HttpGet("headers-audit/secure")]
    public IActionResult HeadersAuditSecure()
    {
        var result = _misconfigService.AuditSecurityHeaders(secureMode: true);
        return Ok(result);
    }
}
