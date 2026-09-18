namespace TechFix.WebApi.Controllers;

using Microsoft.AspNetCore.Mvc;
using TechFix.Application.DTOs;
using TechFix.Application.Interfaces;

[ApiController]
[Route("api/[controller]")]
[Tags("OWASP A7: Cross-Site Scripting (XSS)")]
[Produces("application/json")]
public class A7_XssController : ControllerBase
{
    private readonly IXssService _xssService;

    public A7_XssController(IXssService xssService)
    {
        _xssService = xssService;
    }

    // ==========================================================
    // 1. REFLECTED XSS (CWE-79)
    // ==========================================================

    /// <summary>
    /// Вразливий пошук: пряме відображення вхідного параметра в HTML без екранування (Reflected XSS).
    /// </summary>
    [HttpGet("search/vulnerable")]
    [ProducesResponseType(typeof(ReflectedXssResultDto), StatusCodes.Status200OK)]
    public IActionResult SearchVulnerable([FromQuery] string query = "<script>alert('Reflected-XSS')</script>")
    {
        var result = _xssService.ProcessReflectedSearchVulnerable(query);
        return Ok(result);
    }

    /// <summary>
    /// Захищений пошук: суворе HTML-екранування через System.Text.Encodings.Web.HtmlEncoder.
    /// </summary>
    [HttpGet("search/secure")]
    [ProducesResponseType(typeof(ReflectedXssResultDto), StatusCodes.Status200OK)]
    public IActionResult SearchSecure([FromQuery] string query = "<script>alert('Reflected-XSS')</script>")
    {
        var result = _xssService.ProcessReflectedSearchSecure(query);
        return Ok(result);
    }

    // ==========================================================
    // 2. STORED XSS (CWE-79)
    // ==========================================================

    /// <summary>
    /// Вразливе збереження коментаря: збереження шкідливого скрипта в БД без санітизації (Stored XSS).
    /// </summary>
    [HttpPost("comments/vulnerable")]
    [ProducesResponseType(typeof(CommentXssItemDto), StatusCodes.Status201Created)]
    public async Task<IActionResult> AddCommentVulnerable([FromBody] CommentXssRequestDto request)
    {
        var result = await _xssService.AddCommentVulnerableAsync(request);
        return CreatedAtAction(nameof(GetCommentsVulnerable), new { id = result.Id }, result);
    }

    /// <summary>
    /// Вразливе читання коментарів: повертає збережені коментарі без екранування для клієнтського рендерингу.
    /// </summary>
    [HttpGet("comments/vulnerable")]
    [ProducesResponseType(typeof(IReadOnlyList<CommentXssItemDto>), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetCommentsVulnerable()
    {
        var list = await _xssService.GetCommentsVulnerableAsync();
        return Ok(list);
    }

    /// <summary>
    /// Захищене збереження коментаря: дезінфекція від небезпечних тегів та подій (AntiXSS).
    /// </summary>
    [HttpPost("comments/secure")]
    [ProducesResponseType(typeof(CommentXssItemDto), StatusCodes.Status201Created)]
    public async Task<IActionResult> AddCommentSecure([FromBody] CommentXssRequestDto request)
    {
        var result = await _xssService.AddCommentSecureAsync(request);
        return CreatedAtAction(nameof(GetCommentsSecure), new { id = result.Id }, result);
    }

    /// <summary>
    /// Захищене читання коментарів: повертає повністю екрановані та знешкоджені записи.
    /// </summary>
    [HttpGet("comments/secure")]
    [ProducesResponseType(typeof(IReadOnlyList<CommentXssItemDto>), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetCommentsSecure()
    {
        var list = await _xssService.GetCommentsSecureAsync();
        return Ok(list);
    }

    // ==========================================================
    // 3. DOM-BASED XSS (CWE-79)
    // ==========================================================

    /// <summary>
    /// Вразлива оцінка перенаправлення: клієнтський сінк location.href приймає псевдо-протокол javascript:.
    /// </summary>
    [HttpGet("dom-evaluate/vulnerable")]
    [ProducesResponseType(typeof(DomXssResultDto), StatusCodes.Status200OK)]
    public IActionResult DomEvaluateVulnerable([FromQuery] string redirectUrl = "javascript:alert('DOM-XSS-Execution')")
    {
        var result = _xssService.EvaluateDomXssVulnerable(redirectUrl);
        return Ok(result);
    }

    /// <summary>
    /// Захищена оцінка перенаправлення: валідація схеми URL за білим списком (тільки http/https та відносні шляхи).
    /// </summary>
    [HttpGet("dom-evaluate/secure")]
    [ProducesResponseType(typeof(DomXssResultDto), StatusCodes.Status200OK)]
    public IActionResult DomEvaluateSecure([FromQuery] string redirectUrl = "javascript:alert('DOM-XSS-Execution')")
    {
        var result = _xssService.EvaluateDomXssSecure(redirectUrl);
        return Ok(result);
    }

    // ==========================================================
    // 4. COOKIE THEFT VIA XSS VS HTTPONLY (CWE-1004)
    // ==========================================================

    /// <summary>
    /// Вразливі Cookie: сесійний ідентифікатор видається без прапорця HttpOnly (доступний через document.cookie).
    /// </summary>
    [HttpGet("cookie-audit/vulnerable")]
    [ProducesResponseType(typeof(CookieSecurityAuditDto), StatusCodes.Status200OK)]
    public IActionResult CookieAuditVulnerable()
    {
        Response.Cookies.Append("TechFix_AuthSession", "vulnerable_secret_session_token_999", new CookieOptions
        {
            HttpOnly = false,
            Secure = false,
            SameSite = SameSiteMode.Lax
        });

        var result = _xssService.AuditCookieProtectionVulnerable();
        return Ok(result);
    }

    /// <summary>
    /// Захищені Cookie: прапорець HttpOnly=true блокує доступ з DOM API document.cookie.
    /// </summary>
    [HttpGet("cookie-audit/secure")]
    [ProducesResponseType(typeof(CookieSecurityAuditDto), StatusCodes.Status200OK)]
    public IActionResult CookieAuditSecure()
    {
        Response.Cookies.Append("TechFix_AuthSession", "secure_hmac_protected_token_888", new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict
        });

        var result = _xssService.AuditCookieProtectionSecure();
        return Ok(result);
    }
}
