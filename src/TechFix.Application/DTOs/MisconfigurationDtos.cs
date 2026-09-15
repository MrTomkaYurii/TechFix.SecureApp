namespace TechFix.Application.DTOs;

public class BackupDownloadResponseDto
{
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
    public string FileName { get; set; } = string.Empty;
    public string? ContentPreview { get; set; }
    public string SecurityMode { get; set; } = string.Empty;
}

public class SecurityHeadersAuditDto
{
    public string HeaderName { get; set; } = string.Empty;
    public string? Value { get; set; }
    public string Status { get; set; } = string.Empty;
    public string Recommendation { get; set; } = string.Empty;
}
