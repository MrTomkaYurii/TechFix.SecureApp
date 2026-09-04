using TechFix.Application.DTOs;

namespace TechFix.Application.Interfaces;

public interface IInjectionService
{
    // A1.1: SQL Injection (String & Numeric)
    Task<List<PartDto>> SearchPartsVulnerableSqlAsync(string query);
    Task<List<PartDto>> SearchPartsSecureSqlAsync(string query);
    Task<PartDto?> GetPartByIdVulnerableSqlAsync(string rawId);
    Task<PartDto?> GetPartByIdSecureSqlAsync(int id);

    // A1.2: OS Command Injection
    Task<string> ExecuteDiagnosticPingVulnerableAsync(string hostOrIp);
    Task<string> ExecuteDiagnosticPingSecureAsync(string hostOrIp);

    // A1.3: HTML / iFrame Injection
    Task<string> RenderFeedbackVulnerableHtmlAsync(HtmlInjectionRequest request);
    Task<string> RenderFeedbackSecureHtmlAsync(HtmlInjectionRequest request);

    // A1.4: Mail Header Injection (SMTP CRLF)
    Task<string> SendNotificationVulnerableSmtpAsync(MailHeaderInjectionRequest request);
    Task<string> SendNotificationSecureSmtpAsync(MailHeaderInjectionRequest request);
}
