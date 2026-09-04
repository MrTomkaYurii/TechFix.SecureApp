namespace TechFix.Domain.Entities;

public enum UserRole
{
    Client,
    Technician,
    Support,
    Admin
}

public class User
{
    public int Id { get; set; }
    public string Username { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public string? Salt { get; set; }
    public UserRole Role { get; set; } = UserRole.Client;
    public string SecurityQuestion { get; set; } = "What is your primary phone?";
    public string SecurityAnswer { get; set; } = "0981234567";
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
