namespace TechFix.Application.DTOs;

public class ReflectedXssResultDto
{
    public string Query { get; set; } = string.Empty;
    public string RenderedOutput { get; set; } = string.Empty;
    public bool IsSanitized { get; set; }
    public string Context { get; set; } = string.Empty;
    public string Warning { get; set; } = string.Empty;
}

public class CommentXssRequestDto
{
    public string Author { get; set; } = string.Empty;
    public string Content { get; set; } = string.Empty;
}

public class CommentXssItemDto
{
    public int Id { get; set; }
    public string Author { get; set; } = string.Empty;
    public string RawContent { get; set; } = string.Empty;
    public string SafeHtmlContent { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
}

public class DomXssResultDto
{
    public string ParameterValue { get; set; } = string.Empty;
    public string ClientSinkCode { get; set; } = string.Empty;
    public bool IsVulnerableToDomSink { get; set; }
    public string Explanation { get; set; } = string.Empty;
    public string RemediationAdvice { get; set; } = string.Empty;
}

public class CookieSecurityAuditDto
{
    public string CookieName { get; set; } = string.Empty;
    public bool HttpOnly { get; set; }
    public bool Secure { get; set; }
    public string SameSite { get; set; } = string.Empty;
    public bool CanBeStolenViaDocumentCookie { get; set; }
    public string StatusDescription { get; set; } = string.Empty;
}
