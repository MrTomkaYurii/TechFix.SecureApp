namespace TechFix.Application.DTOs;

public class BasketItemDto
{
    public int Id { get; set; }
    public int PartId { get; set; }
    public string PartName { get; set; } = string.Empty;
    public decimal UnitPrice { get; set; }
    public int Quantity { get; set; }
}

public class BasketDto
{
    public int Id { get; set; }
    public int UserId { get; set; }
    public string UserFullName { get; set; } = string.Empty;
    public List<BasketItemDto> Items { get; set; } = new();
    public decimal TotalAmount => Items.Sum(i => i.UnitPrice * i.Quantity);
}

public class AddBasketItemRequestDto
{
    public int PartId { get; set; }
    public int Quantity { get; set; } = 1;
}

public class FeedbackSubmitRequestDto
{
    public int UserId { get; set; }
    public string ClientName { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public int Rating { get; set; } = 5;
    public string Comment { get; set; } = string.Empty;
}

public class AccessControlResponseDto
{
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
    public object? Data { get; set; }
    public string SecurityMode { get; set; } = string.Empty;
    public bool IsAuthorized { get; set; }
}
