namespace TechFix.Application.DTOs;

public class PartDto
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public decimal Price { get; set; }
    public int StockQuantity { get; set; }
    public string Description { get; set; } = string.Empty;
}

public class SqlSearchRequest
{
    /// <summary>
    /// Search term for Part name or description (e.g. 'Display' or payload ' OR '1'='1)
    /// </summary>
    public string Query { get; set; } = string.Empty;
}

public class CommandInjectionRequest
{
    /// <summary>
    /// IP address or hostname to ping (e.g. 127.0.0.1 or 127.0.0.1; whoami)
    /// </summary>
    public string HostOrIp { get; set; } = string.Empty;
}

public class HtmlInjectionRequest
{
    public string ClientName { get; set; } = string.Empty;
    public string Comment { get; set; } = string.Empty;
}

public class MailHeaderInjectionRequest
{
    public string ToEmail { get; set; } = string.Empty;
    public string Subject { get; set; } = string.Empty;
    public string MessageBody { get; set; } = string.Empty;
}
