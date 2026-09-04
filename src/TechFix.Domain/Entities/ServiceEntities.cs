namespace TechFix.Domain.Entities;

public class CustomerFeedback
{
    public int Id { get; set; }
    public string ClientName { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public int Rating { get; set; } = 5;
    public string Comment { get; set; } = string.Empty;
    public bool IsApproved { get; set; } = true;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}

public class RepairOrder
{
    public int Id { get; set; }
    public string OrderNumber { get; set; } = string.Empty;
    public int ClientId { get; set; }
    public string DeviceModel { get; set; } = string.Empty;
    public string IssueDescription { get; set; } = string.Empty;
    public string Status { get; set; } = "InReview";
    public decimal Cost { get; set; }
    public string TechnicianNotes { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}

public class BasketItem
{
    public int Id { get; set; }
    public int BasketId { get; set; }
    public int PartId { get; set; }
    public string PartName { get; set; } = string.Empty;
    public decimal UnitPrice { get; set; }
    public int Quantity { get; set; }
}

public class Basket
{
    public int Id { get; set; }
    public int UserId { get; set; }
    public string UserFullName { get; set; } = string.Empty;
    public List<BasketItem> Items { get; set; } = new();
    public decimal TotalAmount => Items.Sum(i => i.UnitPrice * i.Quantity);
}
