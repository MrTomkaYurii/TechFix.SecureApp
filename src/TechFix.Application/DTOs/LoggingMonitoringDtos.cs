namespace TechFix.Application.DTOs;

public class LogInjectionRequestDto
{
    public string Username { get; set; } = "attacker%0d%0a[2026-09-25 23:30:00] [INFO] User admin logged in successfully from 192.168.1.100";
    public string AttemptedAction { get; set; } = "PasswordReset";
}

public class LogInjectionResultDto
{
    public string SubmittedInput { get; set; } = string.Empty;
    public string RenderedLogOutput { get; set; } = string.Empty;
    public bool IsPoisoned { get; set; }
    public string Impact { get; set; } = string.Empty;
    public string RemediationAdvice { get; set; } = string.Empty;
}

public class FinancialActionRequestDto
{
    public int OrderId { get; set; } = 42;
    public decimal RefundAmount { get; set; } = 450.00m;
    public string Reason { get; set; } = "Defective laptop display panel refund";
}

public class FinancialActionResultDto
{
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
    public bool AuditTrailRecorded { get; set; }
    public string AuditTelemetrySummary { get; set; } = string.Empty;
    public string SecurityWarning { get; set; } = string.Empty;
}

public class LoginProbeRequestDto
{
    public string TargetUsername { get; set; } = "admin@techfix.local";
    public string IpAddress { get; set; } = "203.0.113.42";
}

public class LoginProbeResultDto
{
    public int FailedAttemptsInWindow { get; set; }
    public bool IsAlertTriggered { get; set; }
    public string AlertLevel { get; set; } = "Normal";
    public string Message { get; set; } = string.Empty;
    public string SiemNotificationPayload { get; set; } = string.Empty;
}

public class SecurityAuditEventDto
{
    public int Id { get; set; }
    public DateTime Timestamp { get; set; }
    public string CorrelationId { get; set; } = string.Empty;
    public string EventType { get; set; } = string.Empty;
    public string Severity { get; set; } = "Info";
    public string ClientIp { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
}
