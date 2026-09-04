using Microsoft.AspNetCore.Mvc;
using TechFix.Application.DTOs;
using TechFix.Application.Interfaces;

namespace TechFix.WebApi.Controllers;

[ApiController]
[Route("api/[controller]")]
[Tags("OWASP A1: Injection (Лабораторна робота №1)")]
public class A1_InjectionController : ControllerBase
{
    private readonly IInjectionService _injectionService;

    public A1_InjectionController(IInjectionService injectionService)
    {
        _injectionService = injectionService;
    }

    #region A1.1: SQL Injection (String & Numeric)

    /// <summary>
    /// Демонстрація рядкової SQL-ін'єкції (Вразливий метод)
    /// Тестовий пейлоад: ' OR '1'='1 або ' UNION SELECT 1, Username, Email, 0, 0, PasswordHash FROM Users--
    /// </summary>
    [HttpPost("sql-search/vulnerable")]
    public async Task<IActionResult> SearchVulnerable([FromBody] SqlSearchRequest request)
    {
        try
        {
            var results = await _injectionService.SearchPartsVulnerableSqlAsync(request.Query);
            return Ok(new
            {
                Status = "Vulnerable Execution Executed",
                Query = request.Query,
                Count = results.Count,
                Data = results
            });
        }
        catch (Exception ex)
        {
            return BadRequest(new { Error = ex.Message, StackTrace = ex.StackTrace });
        }
    }

    /// <summary>
    /// Захищений пошук через параметризовані запити EF Core LINQ (Безпечний метод)
    /// </summary>
    [HttpPost("sql-search/secure")]
    public async Task<IActionResult> SearchSecure([FromBody] SqlSearchRequest request)
    {
        var results = await _injectionService.SearchPartsSecureSqlAsync(request.Query);
        return Ok(new
        {
            Status = "Secure Parameterized Query Executed",
            Query = request.Query,
            Count = results.Count,
            Data = results
        });
    }

    /// <summary>
    /// Числова SQL-ін'єкція за ID деталі (Вразливий метод)
    /// Тестовий пейлоад: 1 OR 1=1
    /// </summary>
    [HttpGet("sql-part/{rawId}/vulnerable")]
    public async Task<IActionResult> GetByIdVulnerable(string rawId)
    {
        try
        {
            var part = await _injectionService.GetPartByIdVulnerableSqlAsync(rawId);
            return Ok(new { Status = "Vulnerable Query Executed", RawId = rawId, Data = part });
        }
        catch (Exception ex)
        {
            return BadRequest(new { Error = ex.Message });
        }
    }

    /// <summary>
    /// Строго типізований запит за ID деталі (Безпечний метод)
    /// </summary>
    [HttpGet("sql-part/{id:int}/secure")]
    public async Task<IActionResult> GetByIdSecure(int id)
    {
        var part = await _injectionService.GetPartByIdSecureSqlAsync(id);
        if (part == null) return NotFound(new { Message = $"Part with ID {id} not found." });
        return Ok(new { Status = "Secure Query Executed", Id = id, Data = part });
    }

    #endregion

    #region A1.2: OS Command Injection

    /// <summary>
    /// Демонстрація виконання команд операційної системи (Вразливий метод)
    /// Тестовий пейлоад: 127.0.0.1 & whoami або 127.0.0.1 & dir
    /// </summary>
    [HttpPost("command-ping/vulnerable")]
    public async Task<IActionResult> PingVulnerable([FromBody] CommandInjectionRequest request)
    {
        var output = await _injectionService.ExecuteDiagnosticPingVulnerableAsync(request.HostOrIp);
        return Ok(new
        {
            Status = "Executed via cmd.exe shell",
            Input = request.HostOrIp,
            CommandOutput = output
        });
    }

    /// <summary>
    /// Захищена перевірка доступності вузла через керований .NET API Ping (Безпечний метод)
    /// </summary>
    [HttpPost("command-ping/secure")]
    public async Task<IActionResult> PingSecure([FromBody] CommandInjectionRequest request)
    {
        var output = await _injectionService.ExecuteDiagnosticPingSecureAsync(request.HostOrIp);
        return Ok(new
        {
            Status = "Executed via Managed NetworkInformation.Ping API",
            Input = request.HostOrIp,
            Result = output
        });
    }

    #endregion

    #region A1.3: HTML / iFrame Injection

    /// <summary>
    /// Рендеринг відгуку клієнта без екранування (Вразливий метод)
    /// Тестовий пейлоад: <h1>Hacked by Yurii</h1><iframe src="http://example.com" width="300" height="200"></iframe>
    /// </summary>
    [HttpPost("html-render/vulnerable")]
    public async Task<IActionResult> RenderHtmlVulnerable([FromBody] HtmlInjectionRequest request)
    {
        var html = await _injectionService.RenderFeedbackVulnerableHtmlAsync(request);
        return Content(html, "text/html");
    }

    /// <summary>
    /// Безпечний рендеринг відгуку з обов'язковим HTML-кодуванням (Безпечний метод)
    /// </summary>
    [HttpPost("html-render/secure")]
    public async Task<IActionResult> RenderHtmlSecure([FromBody] HtmlInjectionRequest request)
    {
        var html = await _injectionService.RenderFeedbackSecureHtmlAsync(request);
        return Content(html, "text/html");
    }

    #endregion

    #region A1.4: Mail Header Injection (SMTP CRLF)

    /// <summary>
    /// Формування поштового сповіщення з несанітизованими заголовками (Вразливий метод)
    /// Тестовий пейлоад ToEmail: client@tntu.edu.ua%0d%0aBcc: director@tntu.edu.ua
    /// </summary>
    [HttpPost("smtp-notify/vulnerable")]
    public async Task<IActionResult> SmtpNotifyVulnerable([FromBody] MailHeaderInjectionRequest request)
    {
        // Декодуємо URL-символи, якщо надійшли у вигляді %0d%0a
        var decodedEmail = Uri.UnescapeDataString(request.ToEmail);
        var decodedSubject = Uri.UnescapeDataString(request.Subject);

        var result = await _injectionService.SendNotificationVulnerableSmtpAsync(new MailHeaderInjectionRequest
        {
            ToEmail = decodedEmail,
            Subject = decodedSubject,
            MessageBody = request.MessageBody
        });

        return Ok(new { Status = "Raw SMTP Packet Formatted", Result = result });
    }

    /// <summary>
    /// Безпечна відправка сповіщення з блокуванням символів CRLF (\r\n) у заголовках (Безпечний метод)
    /// </summary>
    [HttpPost("smtp-notify/secure")]
    public async Task<IActionResult> SmtpNotifySecure([FromBody] MailHeaderInjectionRequest request)
    {
        var decodedEmail = Uri.UnescapeDataString(request.ToEmail);
        var decodedSubject = Uri.UnescapeDataString(request.Subject);

        var result = await _injectionService.SendNotificationSecureSmtpAsync(new MailHeaderInjectionRequest
        {
            ToEmail = decodedEmail,
            Subject = decodedSubject,
            MessageBody = request.MessageBody
        });

        return Ok(new { Status = "Secure SMTP Sanitization", Result = result });
    }

    #endregion
}
