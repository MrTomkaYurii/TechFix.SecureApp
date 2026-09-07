using Microsoft.AspNetCore.Mvc;
using TechFix.Application.DTOs;
using TechFix.Application.Interfaces;

namespace TechFix.WebApi.Controllers;

[ApiController]
[Route("api/[controller]")]
[Tags("OWASP A2: Broken Authentication")]
public class A2_AuthenticationController : ControllerBase
{
    private readonly IAuthenticationService _authService;

    public A2_AuthenticationController(IAuthenticationService authService)
    {
        _authService = authService;
    }

    // ==========================================================
    // 1. INSECURE LOGIN FORM & HARDCODED CREDENTIALS (CWE-798, CWE-522)
    // ==========================================================

    /// <summary>
    /// Вразливий вхід: перевірка пароля у відкритому вигляді та наявність бекдору devadmin (CWE-798, CWE-522).
    /// </summary>
    [HttpPost("login/vulnerable")]
    public async Task<IActionResult> LoginVulnerable([FromBody] LoginRequestDto request)
    {
        var result = await _authService.LoginVulnerablePlaintextAsync(request);
        if (!result.Success) return Unauthorized(result);
        return Ok(result);
    }

    /// <summary>
    /// Захищений вхід: криптографічне соління, хешування PBKDF2-SHA256 та видача підписаного JWT (TTL 15 хв).
    /// </summary>
    [HttpPost("login/secure")]
    public async Task<IActionResult> LoginSecure([FromBody] LoginRequestDto request)
    {
        var result = await _authService.LoginSecureHashedAsync(request);
        if (!result.Success) return Unauthorized(result);
        return Ok(result);
    }

    // ==========================================================
    // 2. LOGOUT MANAGEMENT & SESSION REPLAY (CWE-613, CWE-384)
    // ==========================================================

    /// <summary>
    /// Вразливий вихід: сесія залишається активною на сервері після логауту клієнта (Session Replay).
    /// </summary>
    [HttpPost("logout/vulnerable")]
    public async Task<IActionResult> LogoutVulnerable([FromBody] LogoutRequestDto request)
    {
        var message = await _authService.LogoutVulnerableAsync(request);
        return Ok(new { Status = "Logout Completed (Client-Side Only)", Details = message });
    }

    /// <summary>
    /// Захищений вихід: серверна інвалідація сесії та внесення токена у Revocation Blacklist.
    /// </summary>
    [HttpPost("logout/secure")]
    public async Task<IActionResult> LogoutSecure([FromBody] LogoutRequestDto request)
    {
        var message = await _authService.LogoutSecureAsync(request);
        return Ok(new { Status = "Logout Completed (Server Revocation)", Details = message });
    }

    /// <summary>
    /// Перевірка активності сесії: демонструє, що вразлива сесія активна навіть після "виходу".
    /// </summary>
    [HttpGet("session/vulnerable/{sessionId}")]
    public async Task<IActionResult> CheckSessionVulnerable(string sessionId)
    {
        var result = await _authService.CheckSessionVulnerableAsync(sessionId);
        return Ok(result);
    }

    /// <summary>
    /// Перевірка захищеного токена: блокує доступ, якщо токен додано у Revocation Blacklist.
    /// </summary>
    [HttpGet("session/secure")]
    public async Task<IActionResult> CheckSessionSecure([FromHeader(Name = "Authorization")] string? authorization)
    {
        if (string.IsNullOrEmpty(authorization) || !authorization.StartsWith("Bearer "))
        {
            return Unauthorized(new { Message = "Потрібен заголовок Authorization: Bearer <token>" });
        }

        var token = authorization["Bearer ".Length..].Trim();
        var result = await _authService.CheckSessionSecureAsync(token);
        return Ok(result);
    }

    // ==========================================================
    // 3. BRUTE FORCE ATTACKS & RATE LIMITING (CWE-307, CWE-204)
    // ==========================================================

    /// <summary>
    /// Вразливий перебір паролів: відсутній ліміт запитів, розкриття наявності облікового запису (User Enumeration).
    /// </summary>
    [HttpPost("bruteforce/vulnerable")]
    public async Task<IActionResult> BruteForceVulnerable([FromBody] BruteForceLoginRequestDto request)
    {
        var result = await _authService.LoginBruteForceVulnerableAsync(request);
        if (!result.Success) return Unauthorized(result);
        return Ok(result);
    }

    /// <summary>
    /// Захист від перебору: блокування акаунта після 3 невдалих спроб (Account Lockout) та уніфіковані помилки.
    /// </summary>
    [HttpPost("bruteforce/secure")]
    public async Task<IActionResult> BruteForceSecure([FromBody] BruteForceLoginRequestDto request)
    {
        var result = await _authService.LoginBruteForceSecureAsync(request);
        if (result.IsLockedOut)
        {
            return StatusCode(429, result); // 429 Too Many Requests
        }
        if (!result.Success)
        {
            return Unauthorized(result);
        }
        return Ok(result);
    }

    // ==========================================================
    // 4. ADMINISTRATIVE PORTALS & COOKIE TAMPERING (CWE-565, CWE-287)
    // ==========================================================

    /// <summary>
    /// Вразливий адмін-портал: доступ на основі непідписаного cookie 'admin=1' або заголовка X-User-Role.
    /// </summary>
    [HttpGet("admin-portal/vulnerable")]
    public async Task<IActionResult> AccessAdminPortalVulnerable(
        [FromHeader(Name = "Cookie")] string? cookieHeader,
        [FromHeader(Name = "X-User-Role")] string? roleHeader)
    {
        var result = await _authService.AccessAdminPortalVulnerableAsync(cookieHeader, roleHeader);
        if (!result.AccessGranted) return StatusCode(403, result);
        return Ok(result);
    }

    /// <summary>
    /// Захищений адмін-портал: обов'язкова валідація криптографічно підписаного JWT токена з роллю Admin.
    /// </summary>
    [HttpGet("admin-portal/secure")]
    public async Task<IActionResult> AccessAdminPortalSecure(
        [FromHeader(Name = "Authorization")] string? authorization)
    {
        var result = await _authService.AccessAdminPortalSecureAsync(authorization);
        if (!result.AccessGranted) return StatusCode(403, result);
        return Ok(result);
    }

    // ==========================================================
    // 5. PASSWORD RESET & AUTHENTICATION BYPASS (CWE-287, CWE-640)
    // ==========================================================

    /// <summary>
    /// Вразливе скидання пароля: обхід перевірки через підміну параметрів (SecQuestion10) або пусту відповідь.
    /// </summary>
    [HttpPost("password-reset/vulnerable")]
    public async Task<IActionResult> ResetPasswordVulnerable([FromBody] PasswordResetVulnerableDto request)
    {
        var result = await _authService.ResetPasswordVulnerableAsync(request);
        return Ok(result);
    }

    /// <summary>
    /// Захист 1: Запит одноразового криптографічного токена відновлення з обмеженим терміном дії (15 хв).
    /// </summary>
    [HttpPost("password-reset/request-token-secure")]
    public async Task<IActionResult> RequestResetTokenSecure([FromQuery] string usernameOrEmail)
    {
        var result = await _authService.RequestPasswordResetTokenSecureAsync(usernameOrEmail);
        return Ok(result);
    }

    /// <summary>
    /// Захист 2: Скидання пароля за одноразовим токеном з автоматичною інвалідацією та PBKDF2 хешуванням.
    /// </summary>
    [HttpPost("password-reset/secure")]
    public async Task<IActionResult> ResetPasswordSecure([FromBody] PasswordResetSecureRequestDto request)
    {
        var result = await _authService.ResetPasswordSecureAsync(request);
        return Ok(result);
    }

    // ==========================================================
    // 6. JWT SIGNATURE STRIPPING (alg: none - CVE-2015-9235)
    // ==========================================================

    /// <summary>
    /// Допоміжний метод: генерація легітимного токена та експлойт-токена з alg: none для тестування.
    /// </summary>
    [HttpGet("jwt/sample-tokens")]
    public async Task<IActionResult> GetSampleJwts([FromQuery] string username = "jerry", [FromQuery] string role = "Client")
    {
        var result = await _authService.GenerateSampleJwtAsync(username, role);
        return Ok(result);
    }

    /// <summary>
    /// Вразлива верифікація JWT: приймає токени з alg: none без перевірки цифрового підпису.
    /// </summary>
    [HttpPost("jwt-verify/vulnerable")]
    public async Task<IActionResult> VerifyJwtVulnerable([FromBody] JwtVerificationRequestDto request)
    {
        var result = await _authService.VerifyJwtVulnerableAsync(request.Token);
        return Ok(result);
    }

    /// <summary>
    /// Захищена верифікація JWT: вимагає строгий HMAC-SHA256 підпис, блокує alg: none та підробку Claims.
    /// </summary>
    [HttpPost("jwt-verify/secure")]
    public async Task<IActionResult> VerifyJwtSecure([FromBody] JwtVerificationRequestDto request)
    {
        var result = await _authService.VerifyJwtSecureAsync(request.Token);
        return Ok(result);
    }

    // ==========================================================
    // 7. RAINBOW TABLES & PASSWORD HASHING (CWE-328, CWE-916)
    // ==========================================================

    /// <summary>
    /// Демонстрація порівняння стійкості: небезпечний MD5/SHA-1 проти криптографічно стійкого соленого PBKDF2.
    /// </summary>
    [HttpGet("rainbow-table-demo")]
    public IActionResult GetRainbowTableDemo([FromQuery] string samplePassword = "Passw0rd!")
    {
        var result = _authService.GetRainbowTableDemonstration(samplePassword);
        return Ok(result);
    }
}
