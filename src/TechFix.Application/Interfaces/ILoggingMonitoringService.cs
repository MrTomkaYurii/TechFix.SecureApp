namespace TechFix.Application.Interfaces;
using TechFix.Application.DTOs;

public interface ILoggingMonitoringService
{
    // Task 1: Log Injection / CRLF Log Poisoning
    Task<LogInjectionResultDto> ProcessLogInjectionVulnerableAsync(LogInjectionRequestDto request);
    Task<LogInjectionResultDto> ProcessLogInjectionSecureAsync(LogInjectionRequestDto request);

    // Task 2: Audit Trail Completeness
    Task<FinancialActionResultDto> ProcessFinancialActionVulnerableAsync(FinancialActionRequestDto request);
    Task<FinancialActionResultDto> ProcessFinancialActionSecureAsync(FinancialActionRequestDto request, string clientIp);

    // Task 3: Incident Detection & Alerting
    Task<LoginProbeResultDto> ProcessLoginProbeVulnerableAsync(LoginProbeRequestDto request);
    Task<LoginProbeResultDto> ProcessLoginProbeSecureAsync(LoginProbeRequestDto request);

    // Task 4: Security Telemetry Query
    Task<IReadOnlyList<SecurityAuditEventDto>> GetRecentAuditEventsAsync();
}
