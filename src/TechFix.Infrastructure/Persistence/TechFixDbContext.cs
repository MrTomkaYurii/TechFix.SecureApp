using Microsoft.EntityFrameworkCore;
using TechFix.Domain.Entities;

namespace TechFix.Infrastructure.Persistence;

public class TechFixDbContext : DbContext
{
    public TechFixDbContext(DbContextOptions<TechFixDbContext> options) : base(options)
    {
    }

    public DbSet<Part> Parts => Set<Part>();
    public DbSet<User> Users => Set<User>();
    public DbSet<RepairOrder> RepairOrders => Set<RepairOrder>();
    public DbSet<CustomerFeedback> Feedbacks => Set<CustomerFeedback>();
    public DbSet<Basket> Baskets => Set<Basket>();
    public DbSet<BasketItem> BasketItems => Set<BasketItem>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // Seed Parts
        modelBuilder.Entity<Part>().HasData(
            new Part { Id = 1, Name = "OLED Display Assembly iPhone 14 Pro", Category = "Screens", Price = 4200.00m, StockQuantity = 12, Description = "Original OEM Super Retina XDR display panel" },
            new Part { Id = 2, Name = "Battery Pack 5000mAh Samsung S23", Category = "Batteries", Price = 1150.00m, StockQuantity = 25, Description = "High-capacity lithium-ion replacement battery" },
            new Part { Id = 3, Name = "Charging Port Flex Cable Type-C", Category = "Cables", Price = 380.00m, StockQuantity = 40, Description = "Fast charging dock connector module" },
            new Part { Id = 4, Name = "BGA Soldering Station Flux Paste 50g", Category = "Tools", Price = 290.00m, StockQuantity = 15, Description = "No-clean professional SMD rework soldering flux" },
            new Part { Id = 5, Name = "Motherboard Logic Board MacBook Air M2", Category = "Mainboards", Price = 14500.00m, StockQuantity = 3, Description = "Integrated Apple Silicon logic board 16GB RAM" }
        );

        // Seed Users
        modelBuilder.Entity<User>().HasData(
            new User { Id = 1, Username = "admin", Email = "admin@techfix.tntu.edu.ua", PasswordHash = "Passw0rd!AdminSecure2026", Role = UserRole.Admin, SecurityQuestion = "Master Secret", SecurityAnswer = "CaoimheKeyFile" },
            new User { Id = 2, Username = "student", Email = "tomka.yurii@tntu.edu.ua", PasswordHash = "Passw0rd!", Role = UserRole.Client, SecurityQuestion = "Student City", SecurityAnswer = "Chernivtsi" },
            new User { Id = 3, Username = "jerry", Email = "jerry@techfix.tntu.edu.ua", PasswordHash = "JerrySecret99", Role = UserRole.Technician, SecurityQuestion = "First Pet", SecurityAnswer = "Tom" },
            new User { Id = 4, Username = "support_agent", Email = "support@techfix.tntu.edu.ua", PasswordHash = "KlintIstvud3130", Role = UserRole.Support, SecurityQuestion = "Station Code", SecurityAnswer = "TNTU-122" }
        );

        // Seed Feedbacks
        modelBuilder.Entity<CustomerFeedback>().HasData(
            new CustomerFeedback { Id = 1, ClientName = "Олександр Коваленко", Email = "oleksandr@gmail.com", Rating = 5, Comment = "Швидко замінили дисплей, рекомендую сервіс!" },
            new CustomerFeedback { Id = 2, ClientName = "Ірина Мельник", Email = "melnyk.iryna@ukr.net", Rating = 4, Comment = "Батарею тримає чудово, але чекала 2 дні." }
        );

        // Seed Baskets
        modelBuilder.Entity<Basket>().HasData(
            new Basket { Id = 1, UserId = 1, UserFullName = "Administrator TechFix" },
            new Basket { Id = 2, UserId = 2, UserFullName = "Юрій Томка (СНм-61)" },
            new Basket { Id = 3, UserId = 3, UserFullName = "Jerry Technician" }
        );

        modelBuilder.Entity<BasketItem>().HasData(
            new BasketItem { Id = 1, BasketId = 2, PartId = 1, PartName = "OLED Display Assembly iPhone 14 Pro", UnitPrice = 4200.00m, Quantity = 1 },
            new BasketItem { Id = 2, BasketId = 1, PartId = 5, PartName = "Motherboard Logic Board MacBook Air M2", UnitPrice = 14500.00m, Quantity = 1 }
        );
    }
}
