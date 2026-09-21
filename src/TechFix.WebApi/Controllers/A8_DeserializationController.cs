namespace TechFix.WebApi.Controllers;

using Microsoft.AspNetCore.Mvc;
using TechFix.Application.DTOs;
using TechFix.Application.Interfaces;

[ApiController]
[Route("api/[controller]")]
[Tags("OWASP A8: Insecure Deserialization")]
[Produces("application/json")]
public class A8_DeserializationController : ControllerBase
{
    private readonly IDeserializationService _deserializationService;

    public A8_DeserializationController(IDeserializationService deserializationService)
    {
        _deserializationService = deserializationService;
    }

    // ==========================================================
    // 1. POLYMORPHIC DESERIALIZATION & GADGET CHAINS (CWE-502)
    // ==========================================================

    /// <summary>
    /// Вразлива десеріалізація замовлення: TypeNameHandling.All дозволяє завантаження довільних типів та RCE гаджетів.
    /// </summary>
    [HttpPost("orders/vulnerable")]
    [ProducesResponseType(typeof(OrderSubmissionResultDto), StatusCodes.Status200OK)]
    public async Task<IActionResult> SubmitOrderVulnerable([FromBody] OrderSubmissionRawDto request)
    {
        var result = await _deserializationService.ProcessOrderLinesVulnerableAsync(request);
        return Ok(result);
    }

    /// <summary>
    /// Захищена десеріалізація замовлення: сувора типізація System.Text.Json з ігноруванням $type метаданих.
    /// </summary>
    [HttpPost("orders/secure")]
    [ProducesResponseType(typeof(OrderSubmissionResultDto), StatusCodes.Status200OK)]
    public async Task<IActionResult> SubmitOrderSecure([FromBody] OrderSubmissionRawDto request)
    {
        var result = await _deserializationService.ProcessOrderLinesSecureAsync(request);
        return Ok(result);
    }

    // ==========================================================
    // 2. DENIAL OF SERVICE & REDOS EVALUATION (CWE-400)
    // ==========================================================

    /// <summary>
    /// Вразлива оцінка рядків замовлення: виконання небезпечних виразів або катастрофічного бектрекінгу ReDoS.
    /// </summary>
    [HttpPost("redos/vulnerable")]
    [ProducesResponseType(typeof(OrderSubmissionResultDto), StatusCodes.Status200OK)]
    public async Task<IActionResult> EvaluateOrderLinesVulnerable([FromBody] OrderSubmissionRawDto request)
    {
        var result = await _deserializationService.ProcessOrderLinesVulnerableAsync(request);
        return Ok(result);
    }

    /// <summary>
    /// Захищена оцінка рядків замовлення: блокування виконання динамічних виразів валідатором схеми.
    /// </summary>
    [HttpPost("redos/secure")]
    [ProducesResponseType(typeof(OrderSubmissionResultDto), StatusCodes.Status200OK)]
    public async Task<IActionResult> EvaluateOrderLinesSecure([FromBody] OrderSubmissionRawDto request)
    {
        var result = await _deserializationService.ProcessOrderLinesSecureAsync(request);
        return Ok(result);
    }

    // ==========================================================
    // 3. SERIALIZED SESSION STATE & SIGNATURE AUDIT (CWE-565 / CWE-347)
    // ==========================================================

    /// <summary>
    /// Вразливе відновлення сесії: десеріалізація Base64 об'єкта без перевірки цифрового підпису (підміна ролі на Admin).
    /// </summary>
    [HttpPost("session/vulnerable")]
    [ProducesResponseType(typeof(SessionStateResultDto), StatusCodes.Status200OK)]
    public IActionResult RestoreSessionVulnerable([FromBody] SessionStateRequestDto request)
    {
        var result = _deserializationService.RestoreSessionVulnerable(request.SerializedToken);
        return Ok(result);
    }

    /// <summary>
    /// Захищене відновлення сесії: обов'язкова перевірка криптографічного підпису HMAC-SHA256.
    /// </summary>
    [HttpPost("session/secure")]
    [ProducesResponseType(typeof(SessionStateResultDto), StatusCodes.Status200OK)]
    public IActionResult RestoreSessionSecure([FromBody] SessionStateRequestDto request)
    {
        var result = _deserializationService.RestoreSessionSecure(request.SerializedToken);
        return Ok(result);
    }

    /// <summary>
    /// Генерація легітимного підписаного сесійного токена для тестування захищеної десеріалізації.
    /// </summary>
    [HttpGet("session/generate-signed")]
    [ProducesResponseType(typeof(object), StatusCodes.Status200OK)]
    public IActionResult GenerateSignedSession([FromQuery] int userId = 10, [FromQuery] string username = "regular_user", [FromQuery] string role = "Client")
    {
        var token = _deserializationService.GenerateValidSignedSession(userId, username, role);
        return Ok(new
        {
            Status = "Generated",
            Token = token,
            Usage = "Paste into POST /session/secure SerializedToken field."
        });
    }
}
