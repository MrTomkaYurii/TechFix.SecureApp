namespace TechFix.Application.DTOs;

public class OrderSubmissionRawDto
{
    public string CustomerEmail { get; set; } = "client@techfix.local";
    public string Description { get; set; } = "Repair order for laptop cooling fan";
    /// <summary>
    /// Can contain JSON string or serialized polymorphic object with $type or ReDoS test string.
    /// </summary>
    public string OrderLinesData { get; set; } = string.Empty;
}

public class OrderSubmissionResultDto
{
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
    public int ParsedItemCount { get; set; }
    public string ProcessedType { get; set; } = string.Empty;
    public double ExecutionTimeMs { get; set; }
    public string SecurityAuditNote { get; set; } = string.Empty;
}

public class OrderLineItemDto
{
    public int PartId { get; set; }
    public string PartName { get; set; } = string.Empty;
    public int Quantity { get; set; }
    public decimal UnitPrice { get; set; }
}

public class SessionStateRequestDto
{
    public string SerializedToken { get; set; } = string.Empty;
}

public class SessionStateResultDto
{
    public bool Success { get; set; }
    public int UserId { get; set; }
    public string Username { get; set; } = string.Empty;
    public string Role { get; set; } = string.Empty;
    public bool IsAdmin { get; set; }
    public bool IsSignatureVerified { get; set; }
    public string SecurityStatus { get; set; } = string.Empty;
}

public class SessionTokenPayloadDto
{
    public int UserId { get; set; }
    public string Username { get; set; } = string.Empty;
    public string Role { get; set; } = "Client";
    public bool IsAdmin { get; set; }
    public DateTime ValidUntil { get; set; }
}

public class DiagnosticGadgetCommand
{
    public string Action { get; set; } = "SystemDiagnostics";
    public string ExecutableTarget { get; set; } = "powershell.exe";
    public string Arguments { get; set; } = "-Command Get-Process";
}
