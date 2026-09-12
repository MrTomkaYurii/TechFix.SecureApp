using Microsoft.EntityFrameworkCore;
using TechFix.Application.DTOs;
using TechFix.Application.Interfaces;
using TechFix.Domain.Entities;
using TechFix.Infrastructure.Persistence;

namespace TechFix.Infrastructure.Services;

public class AccessControlService : IAccessControlService
{
    private readonly TechFixDbContext _context;

    public AccessControlService(TechFixDbContext context)
    {
        _context = context;
    }

    // ==========================================
    // 1. INSECURE DIRECT OBJECT REFERENCES (IDOR)
    // ==========================================

    public async Task<AccessControlResponseDto> GetBasketVulnerableAsync(int basketId)
    {
        // ВРАЗЛИВІСТЬ (CWE-639: Insecure Direct Object References - IDOR)
        // АНТИПАТЕРН: Пряме звернення до первинного ключа BasketId без перевірки належності кошика поточному користувачу
        var basket = await _context.Baskets
            .Include(b => b.Items)
            .FirstOrDefaultAsync(b => b.Id == basketId);

        if (basket == null)
        {
            return new AccessControlResponseDto
            {
                Success = false,
                Message = $"Кошик з ID {basketId} не знайдений.",
                SecurityMode = "Vulnerable"
            };
        }

        var dto = new BasketDto
        {
            Id = basket.Id,
            UserId = basket.UserId,
            UserFullName = basket.UserFullName,
            Items = basket.Items.Select(i => new BasketItemDto
            {
                Id = i.Id,
                PartId = i.PartId,
                PartName = i.PartName,
                UnitPrice = i.UnitPrice,
                Quantity = i.Quantity
            }).ToList()
        };

        return new AccessControlResponseDto
        {
            Success = true,
            Message = $"[ВРАЗЛИВИЙ ДОСТУП]: Отримано кошик користувача '{basket.UserFullName}' (UserId: {basket.UserId}). Жодної перевірки прав власності не виконано (CWE-639 IDOR)!",
            Data = dto,
            IsAuthorized = true,
            SecurityMode = "Vulnerable (IDOR / No Ownership Verification)"
        };
    }

    public async Task<AccessControlResponseDto> GetBasketSecureAsync(int basketId, int currentUserId)
    {
        // ЗАХИЩЕНА РЕАЛІЗАЦІЯ (Secure by Design: Contextual Ownership Check)
        // Сервер обов'язково перевіряє, чи належить запитуваний ресурс поточному автентифікованому користувачу
        var basket = await _context.Baskets
            .Include(b => b.Items)
            .FirstOrDefaultAsync(b => b.Id == basketId);

        if (basket == null)
        {
            return new AccessControlResponseDto
            {
                Success = false,
                Message = $"Кошик з ID {basketId} не знайдений.",
                SecurityMode = "Secure"
            };
        }

        // Перевірка прав власності
        if (basket.UserId != currentUserId && currentUserId != 1) // 1 = Admin
        {
            return new AccessControlResponseDto
            {
                Success = false,
                Message = $"Security Alert: Спроба несанкціонованого доступу до чужого ресурсу (IDOR заблоковано)! Користувач з ID {currentUserId} не є власником кошика {basketId} (власник: UserId {basket.UserId}).",
                Data = null,
                IsAuthorized = false,
                SecurityMode = "Secure (IDOR Neutralized: Ownership Enforced)"
            };
        }

        var dto = new BasketDto
        {
            Id = basket.Id,
            UserId = basket.UserId,
            UserFullName = basket.UserFullName,
            Items = basket.Items.Select(i => new BasketItemDto
            {
                Id = i.Id,
                PartId = i.PartId,
                PartName = i.PartName,
                UnitPrice = i.UnitPrice,
                Quantity = i.Quantity
            }).ToList()
        };

        return new AccessControlResponseDto
        {
            Success = true,
            Message = "Доступ дозволено: підтверджено право власності на запитуваний кошик.",
            Data = dto,
            IsAuthorized = true,
            SecurityMode = "Secure"
        };
    }

    // ==========================================
    // 2. MANIPULATING ANOTHER USER'S BASKET ITEMS
    // ==========================================

    public async Task<AccessControlResponseDto> AddItemToBasketVulnerableAsync(int basketId, AddBasketItemRequestDto item)
    {
        var basket = await _context.Baskets.Include(b => b.Items).FirstOrDefaultAsync(b => b.Id == basketId);
        if (basket == null) return new AccessControlResponseDto { Success = false, Message = "Кошик не знайдено." };

        var part = await _context.Parts.FindAsync(item.PartId);
        if (part == null) return new AccessControlResponseDto { Success = false, Message = "Товар не знайдено." };

        var newItem = new BasketItem
        {
            BasketId = basket.Id,
            PartId = part.Id,
            PartName = part.Name,
            UnitPrice = part.Price,
            Quantity = item.Quantity
        };

        _context.BasketItems.Add(newItem);
        await _context.SaveChangesAsync();

        return new AccessControlResponseDto
        {
            Success = true,
            Message = $"[IDOR ВРАЗЛИВІСТЬ]: Товар '{part.Name}' успішно додано до чужого кошика {basketId} користувача '{basket.UserFullName}' без авторизації!",
            Data = newItem,
            SecurityMode = "Vulnerable"
        };
    }

    public async Task<AccessControlResponseDto> AddItemToBasketSecureAsync(int basketId, AddBasketItemRequestDto item, int currentUserId)
    {
        var basket = await _context.Baskets.FirstOrDefaultAsync(b => b.Id == basketId);
        if (basket == null) return new AccessControlResponseDto { Success = false, Message = "Кошик не знайдено." };

        if (basket.UserId != currentUserId)
        {
            return new AccessControlResponseDto
            {
                Success = false,
                Message = $"Security Alert: Відхилено спробу модифікації чужого кошика! Користувач {currentUserId} не має права додавати товари до кошика {basketId}.",
                SecurityMode = "Secure (Unauthorized Manipulation Blocked)"
            };
        }

        var part = await _context.Parts.FindAsync(item.PartId);
        if (part == null) return new AccessControlResponseDto { Success = false, Message = "Товар не знайдено." };

        var newItem = new BasketItem
        {
            BasketId = basket.Id,
            PartId = part.Id,
            PartName = part.Name,
            UnitPrice = part.Price,
            Quantity = item.Quantity
        };

        _context.BasketItems.Add(newItem);
        await _context.SaveChangesAsync();

        return new AccessControlResponseDto
        {
            Success = true,
            Message = "Товар успішно додано до вашого кошика після перевірки прав доступу.",
            Data = newItem,
            SecurityMode = "Secure"
        };
    }

    // ==========================================
    // 3. PARAMETER TAMPERING / IMPERSONATION
    // ==========================================

    public async Task<AccessControlResponseDto> SubmitFeedbackVulnerableAsync(FeedbackSubmitRequestDto request)
    {
        // ВРАЗЛИВІСТЬ (CWE-284: Improper Access Control / Impersonation)
        // АНТИПАТЕРН: Довіра до переданого клієнтом ідентифікатора UserId та імені ClientName
        var feedback = new CustomerFeedback
        {
            ClientName = request.ClientName,
            Email = request.Email,
            Rating = request.Rating,
            Comment = request.Comment
        };

        _context.Feedbacks.Add(feedback);
        await _context.SaveChangesAsync();

        return new AccessControlResponseDto
        {
            Success = true,
            Message = $"[УРАЗЛИВІСТЬ ПІДМІНИ ОСОБИ]: Відгук опубліковано від імені користувача '{request.ClientName}' (UserId: {request.UserId}). Довіра до параметрів клієнта дозволила спуфінг відгуку!",
            Data = feedback,
            SecurityMode = "Vulnerable (User Impersonation)"
        };
    }

    public async Task<AccessControlResponseDto> SubmitFeedbackSecureAsync(FeedbackSubmitRequestDto request, int currentUserId)
    {
        // ЗАХИЩЕНА РЕАЛІЗАЦІЯ: Ігнорування клієнтського UserId, обов'язкове вилучення ідентичності з захищеного контексту сесії/JWT
        var currentUser = await _context.Users.FindAsync(currentUserId);
        if (currentUser == null)
        {
            return new AccessControlResponseDto { Success = false, Message = "Неавтентифікований користувач." };
        }

        var feedback = new CustomerFeedback
        {
            ClientName = currentUser.Username, // Жорстка прив'язка до автентифікованого користувача
            Email = currentUser.Email,
            Rating = request.Rating,
            Comment = request.Comment
        };

        _context.Feedbacks.Add(feedback);
        await _context.SaveChangesAsync();

        return new AccessControlResponseDto
        {
            Success = true,
            Message = $"Відгук безпечно зареєстровано. Авторство гарантовано автентифікованим обліковим записом '{currentUser.Username}' (UserId: {currentUserId}). Підміна особи неможлива.",
            Data = feedback,
            SecurityMode = "Secure"
        };
    }

    // ==========================================
    // 4. MISSING FUNCTION LEVEL ACCESS CONTROL
    // ==========================================

    public async Task<AccessControlResponseDto> GetHiddenAdminPortalVulnerableAsync()
    {
        // ВРАЗЛИВІСТЬ (CWE-285: Missing Function Level Access Control / Relying on Obscurity)
        // Ендпоінт просто прихований у меню сайту, але не має жодної перевірки прав на сервері
        var allUsers = await _context.Users.Select(u => new
        {
            u.Id,
            u.Username,
            u.Email,
            u.Role,
            u.PasswordHash
        }).ToListAsync();

        return new AccessControlResponseDto
        {
            Success = true,
            Message = "[ВРАЗЛИВІСТЬ ОБСКУРАНТИЗМУ]: Доступ до прихованої секції адміністратора надано без перевірки ролей! Розкрито всіх користувачів та їхні хеші.",
            Data = allUsers,
            SecurityMode = "Vulnerable (Security through Obscurity)"
        };
    }

    public async Task<AccessControlResponseDto> GetHiddenAdminPortalSecureAsync(string userRole)
    {
        // ЗАХИЩЕНА РЕАЛІЗАЦІЯ: Рольова перевірка (Role-Based Access Control - RBAC)
        if (!string.Equals(userRole, "Admin", StringComparison.OrdinalIgnoreCase))
        {
            return new AccessControlResponseDto
            {
                Success = false,
                Message = $"Security Alert: 403 Forbidden. Поточна роль '{userRole}' не має доступу до цієї адміністративної функції. Потрібна роль 'Admin'.",
                SecurityMode = "Secure (RBAC Enforced)"
            };
        }

        var allUsers = await _context.Users.Select(u => new
        {
            u.Id,
            u.Username,
            u.Email,
            u.Role
        }).ToListAsync();

        return new AccessControlResponseDto
        {
            Success = true,
            Message = "Адміністративний доступ підтверджено на основі перевірки ролі Admin.",
            Data = allUsers,
            SecurityMode = "Secure"
        };
    }
}
