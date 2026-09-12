using Microsoft.AspNetCore.Mvc;
using TechFix.Application.DTOs;
using TechFix.Application.Interfaces;

namespace TechFix.WebApi.Controllers;

[ApiController]
[Route("api/[controller]")]
[Tags("OWASP A5: Broken Access Control")]
public class A5_AccessControlController : ControllerBase
{
    private readonly IAccessControlService _accessControlService;

    public A5_AccessControlController(IAccessControlService accessControlService)
    {
        _accessControlService = accessControlService;
    }

    // ==========================================================
    // 1. INSECURE DIRECT OBJECT REFERENCES (IDOR) - BASKET
    // ==========================================================

    /// <summary>
    /// Вразливий доступ до кошика (IDOR): повертає деталі будь-якого кошика за прямим ID без перевірки власника.
    /// </summary>
    [HttpGet("basket/{basketId:int}/vulnerable")]
    public async Task<IActionResult> GetBasketVulnerable(int basketId)
    {
        var result = await _accessControlService.GetBasketVulnerableAsync(basketId);
        return Ok(result);
    }

    /// <summary>
    /// Захищений доступ до кошика: перевіряє право власності (CurrentUserId = 2 - Юрій Томка) і блокує доступ до кошика Admin (1).
    /// </summary>
    [HttpGet("basket/{basketId:int}/secure")]
    public async Task<IActionResult> GetBasketSecure(int basketId, [FromHeader(Name = "X-Current-UserId")] int currentUserId = 2)
    {
        var result = await _accessControlService.GetBasketSecureAsync(basketId, currentUserId);
        if (!result.Success && !result.IsAuthorized)
        {
            return StatusCode(403, result); // 403 Forbidden
        }
        return Ok(result);
    }

    // ==========================================================
    // 2. BASKET ITEM MANIPULATION
    // ==========================================================

    /// <summary>
    /// Вразливе додавання товару (IDOR): дозволяє додати товар до кошика іншого користувача.
    /// </summary>
    [HttpPost("basket/{basketId:int}/items/vulnerable")]
    public async Task<IActionResult> AddItemVulnerable(int basketId, [FromBody] AddBasketItemRequestDto item)
    {
        var result = await _accessControlService.AddItemToBasketVulnerableAsync(basketId, item);
        return Ok(result);
    }

    /// <summary>
    /// Захищене додавання товару: блокує модифікацію чужого кошика.
    /// </summary>
    [HttpPost("basket/{basketId:int}/items/secure")]
    public async Task<IActionResult> AddItemSecure(int basketId, [FromBody] AddBasketItemRequestDto item, [FromHeader(Name = "X-Current-UserId")] int currentUserId = 2)
    {
        var result = await _accessControlService.AddItemToBasketSecureAsync(basketId, item, currentUserId);
        if (!result.Success) return StatusCode(403, result);
        return Ok(result);
    }

    // ==========================================================
    // 3. PARAMETER TAMPERING / IMPERSONATION
    // ==========================================================

    /// <summary>
    /// Вразливий відгук: дозволяє підробити автора відгуку через параметр UserId та ClientName (Спуфінг).
    /// </summary>
    [HttpPost("feedback/vulnerable")]
    public async Task<IActionResult> SubmitFeedbackVulnerable([FromBody] FeedbackSubmitRequestDto request)
    {
        var result = await _accessControlService.SubmitFeedbackVulnerableAsync(request);
        return Ok(result);
    }

    /// <summary>
    /// Захищений відгук: ігнорує передані дані автора та жорстко прив'язує відгук до автентифікованого користувача.
    /// </summary>
    [HttpPost("feedback/secure")]
    public async Task<IActionResult> SubmitFeedbackSecure([FromBody] FeedbackSubmitRequestDto request, [FromHeader(Name = "X-Current-UserId")] int currentUserId = 2)
    {
        var result = await _accessControlService.SubmitFeedbackSecureAsync(request, currentUserId);
        return Ok(result);
    }

    // ==========================================================
    // 4. MISSING FUNCTION LEVEL ACCESS CONTROL
    // ==========================================================

    /// <summary>
    /// Вразлива адмін-функція: прихована сторінка експорту користувачів доступна будь-кому без перевірки прав.
    /// </summary>
    [HttpGet("hidden-admin-data/vulnerable")]
    public async Task<IActionResult> GetHiddenAdminVulnerable()
    {
        var result = await _accessControlService.GetHiddenAdminPortalVulnerableAsync();
        return Ok(result);
    }

    /// <summary>
    /// Захищена адмін-функція: обов'язкова перевірка ролі 'Admin'.
    /// </summary>
    [HttpGet("hidden-admin-data/secure")]
    public async Task<IActionResult> GetHiddenAdminSecure([FromHeader(Name = "X-User-Role")] string userRole = "Client")
    {
        var result = await _accessControlService.GetHiddenAdminPortalSecureAsync(userRole);
        if (!result.Success) return StatusCode(403, result);
        return Ok(result);
    }
}
