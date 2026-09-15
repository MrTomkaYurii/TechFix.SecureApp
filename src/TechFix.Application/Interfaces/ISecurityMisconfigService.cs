using TechFix.Application.DTOs;

namespace TechFix.Application.Interfaces;

public interface ISecurityMisconfigService
{
    // Task 1: Unhandled exceptions & Stack trace leaks
    Task<object> TriggerErrorVulnerableAsync(string trigger);
    Task<object> TriggerErrorSecureAsync(string trigger);

    // Task 2: Accessing exposed backup & configuration files
    Task<BackupDownloadResponseDto> AccessBackupFileVulnerableAsync(string fileName);
    Task<BackupDownloadResponseDto> AccessBackupFileSecureAsync(string fileName);

    // Task 3: Developer comments & credentials left in client scripts
    Task<object> GetSupportCredentialsLeakVulnerableAsync();
    Task<object> GetSupportCredentialsLeakSecureAsync();

    // Task 4: Security headers & CORS audit
    List<SecurityHeadersAuditDto> AuditSecurityHeaders(bool secureMode);
}
