namespace TechFix.Application.DTOs;

public class XmlOrderParseRequestDto
{
    public string XmlContent { get; set; } = string.Empty;
}

public class XmlOrderParseResponseDto
{
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
    public string? CustomerName { get; set; }
    public string? DeviceModel { get; set; }
    public string? ProblemDescription { get; set; }
    public string? LeakedData { get; set; }
    public string SecurityMode { get; set; } = string.Empty;
    public long ExecutionTimeMs { get; set; }
}

public class BlindXxeRequestDto
{
    public string XmlContent { get; set; } = string.Empty;
}
