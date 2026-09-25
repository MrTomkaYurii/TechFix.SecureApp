namespace TechFix.Infrastructure.Services;

using System.Text.RegularExpressions;
using TechFix.Application.DTOs;
using TechFix.Application.Interfaces;

public class LoggingMonitoringService : ILoggingMonitoringService
{
    private static readonly List<SecurityAuditEventDto> _auditEvents = new()
    {
        new SecurityAuditEventDto
        {
            Id = 1,
            Timestamp = DateTime.UtcNow.AddMinutes(-30),
            CorrelationId = "a10-init-system-boot",
            EventType = "SYSTEM_STARTUP",
            Severity = "Information",
            ClientIp = "127.0.0.1",
            Message = "TechFix Core Security Engine initialized successfully."
        }
    };

    private static readonly Dictionary<string, int> _failedAttempts = new();
    private static readonly object _syncLock = new();

    public Task<LogInjectionResultDto> ProcessLogInjectionVulnerableAsync(LogInjectionRequestDto request)
    {
        // Vulnerable: raw string concatenation without sanitizing CRLF
        var decodedUser = Uri.UnescapeDataString(request.Username ?? string.Empty);
        var rawLog = $"[2026-09-25 23:30:15] [WARN] [AuthService] Authentication failed for user: {decodedUser} on action {request.AttemptedAction}";

        bool isPoisoned = decodedUser.Contains("\r") || decodedUser.Contains("\n");

        var result = new LogInjectionResultDto
        {
            SubmittedInput = request.Username ?? string.Empty,
            RenderedLogOutput = rawLog,
            IsPoisoned = isPoisoned,
            Impact = isPoisoned
                ? "VULNERABLE (CWE-117): CRLF Log Injection successful! Attacker injected newline characters to forge fake log entries (Log Spoofing), corrupting audit trails."
                : "No newline characters detected in input, but raw string format remains vulnerable.",
            RemediationAdvice = "Never concatenate untrusted user input directly into unstructured log strings. Strip CR/LF characters or adopt structured JSON log format."
        };

        return Task.FromResult(result);
    }

    public Task<LogInjectionResultDto> ProcessLogInjectionSecureAsync(LogInjectionRequestDto request)
    {
        var rawInput = Uri.UnescapeDataString(request.Username ?? string.Empty);

        // Secure: 1. Strip CR/LF characters
        var sanitizedUser = Regex.Replace(rawInput, @"[\r\n]", "_");

        // 2. Format as immutable structured JSON telemetry
        var structuredLog = $"{{\"timestamp\":\"{DateTime.UtcNow:O}\",\"level\":\"Warning\",\"service\":\"AuthService\",\"event\":\"AuthenticationFailed\",\"user\":\"{sanitizedUser}\",\"action\":\"{request.AttemptedAction}\"}}";

        var result = new LogInjectionResultDto
        {
            SubmittedInput = request.Username ?? string.Empty,
            RenderedLogOutput = structuredLog,
            IsPoisoned = false,
            Impact = "SECURED: Input sanitized by replacing CRLF characters with neutral placeholders, and rendered as structured JSON telemetry.",
            RemediationAdvice = "Adopt structured logging with Serilog/System.Text.Json to guarantee that user input cannot alter log record framing."
        };

        return Task.FromResult(result);
    }

    public Task<FinancialActionResultDto> ProcessFinancialActionVulnerableAsync(FinancialActionRequestDto request)
    {
        // Vulnerable: Silent financial operation without recording actor, IP, or immutable audit trail
        var result = new FinancialActionResultDto
        {
            Success = true,
            Message = $"Refund of ${request.RefundAmount} for Order #{request.OrderId} executed successfully.",
            AuditTrailRecorded = false,
            AuditTelemetrySummary = "None (No audit record written to persistent log)",
            SecurityWarning = "VULNERABLE (CWE-778): Insufficient Logging! Critical financial transaction executed without audit log, actor attribution, or correlation ID."
        };

        return Task.FromResult(result);
    }

    public Task<FinancialActionResultDto> ProcessFinancialActionSecureAsync(FinancialActionRequestDto request, string clientIp)
    {
        var correlationId = Guid.NewGuid().ToString("N");
        var eventId = 0;

        lock (_syncLock)
        {
            eventId = _auditEvents.Count + 1;
            _auditEvents.Add(new SecurityAuditEventDto
            {
                Id = eventId,
                Timestamp = DateTime.UtcNow,
                CorrelationId = correlationId,
                EventType = "FINANCIAL_REFUND",
                Severity = "Critical",
                ClientIp = clientIp,
                Message = $"Refund processed: ${request.RefundAmount} for Order #{request.OrderId}. Reason: '{request.Reason}'."
            });
        }

        var result = new FinancialActionResultDto
        {
            Success = true,
            Message = $"Refund of ${request.RefundAmount} for Order #{request.OrderId} executed successfully and audited.",
            AuditTrailRecorded = true,
            AuditTelemetrySummary = $"Audit Event #{eventId} | CorrelationId: {correlationId} | IP: {clientIp} | Timestamp: {DateTime.UtcNow:O}",
            SecurityWarning = "SECURED: Comprehensive audit record generated with immutable metadata and stored in tamper-evident security telemetry repository."
        };

        return Task.FromResult(result);
    }

    public Task<LoginProbeResultDto> ProcessLoginProbeVulnerableAsync(LoginProbeRequestDto request)
    {
        var key = $"{request.TargetUsername}_{request.IpAddress}";
        int attempts = 0;
        lock (_syncLock)
        {
            _failedAttempts[key] = _failedAttempts.GetValueOrDefault(key, 0) + 1;
            attempts = _failedAttempts[key];
        }

        var result = new LoginProbeResultDto
        {
            FailedAttemptsInWindow = attempts,
            IsAlertTriggered = false,
            AlertLevel = "None (Silent)",
            Message = $"Failed login attempt #{attempts} recorded locally, but monitoring system did not trigger any alert.",
            SiemNotificationPayload = "None"
        };

        return Task.FromResult(result);
    }

    public Task<LoginProbeResultDto> ProcessLoginProbeSecureAsync(LoginProbeRequestDto request)
    {
        var key = $"{request.TargetUsername}_{request.IpAddress}";
        int attempts = 0;
        bool alertTriggered = false;
        string correlationId = Guid.NewGuid().ToString("N");

        lock (_syncLock)
        {
            _failedAttempts[key] = _failedAttempts.GetValueOrDefault(key, 0) + 1;
            attempts = _failedAttempts[key];

            if (attempts >= 3)
            {
                alertTriggered = true;
                _auditEvents.Add(new SecurityAuditEventDto
                {
                    Id = _auditEvents.Count + 1,
                    Timestamp = DateTime.UtcNow,
                    CorrelationId = correlationId,
                    EventType = "BRUTE_FORCE_DETECTED",
                    Severity = "High",
                    ClientIp = request.IpAddress,
                    Message = $"Automated Alert: {attempts} consecutive failed logins for target '{request.TargetUsername}' from IP {request.IpAddress}."
                });
            }
        }

        var siemPayload = alertTriggered
            ? $"{{\"Alert\":\"BRUTE_FORCE_ATTACK\",\"Target\":\"{request.TargetUsername}\",\"SourceIp\":\"{request.IpAddress}\",\"FailedAttempts\":{attempts},\"Action\":\"IP_RATE_LIMITED\",\"CorrelationId\":\"{correlationId}\"}}"
            : "Threshold (3) not yet reached.";

        var result = new LoginProbeResultDto
        {
            FailedAttemptsInWindow = attempts,
            IsAlertTriggered = alertTriggered,
            AlertLevel = alertTriggered ? "High (Security Incident)" : "Normal",
            Message = alertTriggered
                ? $"ALERT TRIGGERED (CWE-392 Mitigated): Automated SIEM dispatch! Multiple failed login attempts detected from {request.IpAddress}."
                : $"Failed login attempt #{attempts} registered. Anomaly monitoring active.",
            SiemNotificationPayload = siemPayload
        };

        return Task.FromResult(result);
    }

    public Task<IReadOnlyList<SecurityAuditEventDto>> GetRecentAuditEventsAsync()
    {
        lock (_syncLock)
        {
            return Task.FromResult<IReadOnlyList<SecurityAuditEventDto>>(_auditEvents.TakeLast(20).ToList());
        }
    }
}
