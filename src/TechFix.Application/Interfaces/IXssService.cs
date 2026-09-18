namespace TechFix.Application.Interfaces;
using TechFix.Application.DTOs;

public interface IXssService
{
    // Task 1: Reflected XSS
    ReflectedXssResultDto ProcessReflectedSearchVulnerable(string query);
    ReflectedXssResultDto ProcessReflectedSearchSecure(string query);

    // Task 2: Stored XSS
    Task<CommentXssItemDto> AddCommentVulnerableAsync(CommentXssRequestDto request);
    Task<IReadOnlyList<CommentXssItemDto>> GetCommentsVulnerableAsync();

    Task<CommentXssItemDto> AddCommentSecureAsync(CommentXssRequestDto request);
    Task<IReadOnlyList<CommentXssItemDto>> GetCommentsSecureAsync();

    // Task 3: DOM-based XSS
    DomXssResultDto EvaluateDomXssVulnerable(string redirectUrl);
    DomXssResultDto EvaluateDomXssSecure(string redirectUrl);

    // Task 4: Cookie Protection (HttpOnly)
    CookieSecurityAuditDto AuditCookieProtectionVulnerable();
    CookieSecurityAuditDto AuditCookieProtectionSecure();
}
