using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Text.Encodings.Web;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using TechFix.Application.DTOs;
using TechFix.Application.Interfaces;
using TechFix.Domain.Entities;
using TechFix.Infrastructure.Persistence;

namespace TechFix.Infrastructure.Services;

public class InjectionService : IInjectionService
{
    private readonly TechFixDbContext _context;

    public InjectionService(TechFixDbContext context)
    {
        _context = context;
    }

    #region A1.1: SQL Injection (String & Numeric)

    /// <summary>
    /// ВРАЗЛИВИЙ МЕТОД: Пряма конкатенація користувацького вводу в SQL-запит (String SQLi).
    /// Дозволяє атаку ' OR '1'='1 або UNION SELECT.
    /// </summary>
    public async Task<List<PartDto>> SearchPartsVulnerableSqlAsync(string query)
    {
        // УВАГА: Антипатерн! Пряма інтерполяція рядків у сирий SQL без параметризації
        var sql = $"SELECT * FROM Parts WHERE Name LIKE '%{query}%' OR Description LIKE '%{query}%'";
        
        var results = await _context.Parts
            .FromSqlRaw(sql)
            .AsNoTracking()
            .ToListAsync();

        return results.Select(p => new PartDto
        {
            Id = p.Id,
            Name = p.Name,
            Category = p.Category,
            Price = p.Price,
            StockQuantity = p.StockQuantity,
            Description = p.Description
        }).ToList();
    }

    /// <summary>
    /// БЕЗПЕЧНИЙ МЕТОД (Secure by Design): Використання EF Core LINQ або параметризованих SQL-запитів.
    /// Запобігає зміні синтаксичного дерева SQL-запиту.
    /// </summary>
    public async Task<List<PartDto>> SearchPartsSecureSqlAsync(string query)
    {
        // Безпечний підхід: EF.Functions.Like або параметризований запит
        var results = await _context.Parts
            .Where(p => EF.Functions.Like(p.Name, $"%{query}%") || EF.Functions.Like(p.Description, $"%{query}%"))
            .AsNoTracking()
            .ToListAsync();

        return results.Select(p => new PartDto
        {
            Id = p.Id,
            Name = p.Name,
            Category = p.Category,
            Price = p.Price,
            StockQuantity = p.StockQuantity,
            Description = p.Description
        }).ToList();
    }

    /// <summary>
    /// ВРАЗЛИВИЙ МЕТОД: Числова SQL-ін'єкція через нетипізований конкатенований параметр Id.
    /// Дозволяє пейлоад 1 OR 1=1.
    /// </summary>
    public async Task<PartDto?> GetPartByIdVulnerableSqlAsync(string rawId)
    {
        // Небезпечно: передача сирого рядка в числовий стовпчик без приведення типу int
        var sql = $"SELECT * FROM Parts WHERE Id = {rawId}";

        var part = await _context.Parts
            .FromSqlRaw(sql)
            .AsNoTracking()
            .FirstOrDefaultAsync();

        if (part == null) return null;

        return new PartDto
        {
            Id = part.Id,
            Name = part.Name,
            Category = part.Category,
            Price = part.Price,
            StockQuantity = part.StockQuantity,
            Description = part.Description
        };
    }

    /// <summary>
    /// БЕЗПЕЧНИЙ МЕТОД: Строга типізація int на рівні DTO / сигнатури методу та FindAsync.
    /// </summary>
    public async Task<PartDto?> GetPartByIdSecureSqlAsync(int id)
    {
        var part = await _context.Parts.FindAsync(id);
        if (part == null) return null;

        return new PartDto
        {
            Id = part.Id,
            Name = part.Name,
            Category = part.Category,
            Price = part.Price,
            StockQuantity = part.StockQuantity,
            Description = part.Description
        };
    }

    #endregion

    #region A1.2: OS Command Injection

    /// <summary>
    /// ВРАЗЛИВИЙ МЕТОД: Передача несанітизованого IP/хосту безпосередньо в системну оболонку cmd.exe.
    /// Дозволяє виконання додаткових команд через оператори & або && або ; (наприклад: 127.0.0.1 & whoami).
    /// </summary>
    public async Task<string> ExecuteDiagnosticPingVulnerableAsync(string hostOrIp)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "cmd.exe",
            Arguments = $"/c ping -n 1 {hostOrIp}",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var process = Process.Start(psi);
        if (process == null) return "Failed to start process.";

        var output = await process.StandardOutput.ReadToEndAsync();
        var error = await process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();

        return string.IsNullOrEmpty(error) ? output : $"{output}\nERROR:\n{error}";
    }

    /// <summary>
    /// БЕЗПЕЧНИЙ МЕТОД (Secure by Design): 
    /// 1. Відмова від виклику командного процесора ОС (cmd/bash).
    /// 2. Використання спеціалізованого .NET API System.Net.NetworkInformation.Ping.
    /// 3. Сувора валідація вхідного хосту/IP регулярним виразом.
    /// </summary>
    public async Task<string> ExecuteDiagnosticPingSecureAsync(string hostOrIp)
    {
        // 1. Сувора валідація формату (заборона будь-яких розділювачів команд &, ;, |, `, $)
        var isHostnameOrIp = Regex.IsMatch(hostOrIp, @"^[a-zA-Z0-9.-]+$");
        if (!isHostnameOrIp)
        {
            return "Security Alert: Invalid hostname or IP address format. Special characters and command separators are strictly rejected.";
        }

        try
        {
            using var pinger = new Ping();
            var reply = await pinger.SendPingAsync(hostOrIp, 1500);
            return $"Diagnostic Result (Managed .NET Ping API): Status={reply.Status}, RoundtripTime={reply.RoundtripTime}ms, Address={reply.Address}";
        }
        catch (Exception ex)
        {
            return $"Diagnostic Error: {ex.Message}";
        }
    }

    #endregion

    #region A1.3: HTML / iFrame Injection

    /// <summary>
    /// ВРАЗЛИВИЙ МЕТОД: Генерація HTML-коду картки відгуку клієнта без екранування.
    /// Зловмисник може впровадити теги <h1>, <iframe src=...>, <script> тощо.
    /// </summary>
    public Task<string> RenderFeedbackVulnerableHtmlAsync(HtmlInjectionRequest request)
    {
        // Небезпечно: вставка сирих рядків у HTML шаблон
        var html = $@"
<div class=""feedback-card"" style=""border: 1px solid #ccc; padding: 10px; margin: 10px 0;"">
    <h3 style=""color: #2b5797;"">Клієнт: {request.ClientName}</h3>
    <p class=""comment"">{request.Comment}</p>
    <small>Статус: Перевірено публічно</small>
</div>";
        return Task.FromResult(html);
    }

    /// <summary>
    /// БЕЗПЕЧНИЙ МЕТОД: Обов'язкове кодування спеціальних символів HTML через HtmlEncoder.Default.Encode().
    /// </summary>
    public Task<string> RenderFeedbackSecureHtmlAsync(HtmlInjectionRequest request)
    {
        var safeClientName = HtmlEncoder.Default.Encode(request.ClientName);
        var safeComment = HtmlEncoder.Default.Encode(request.Comment);

        var html = $@"
<div class=""feedback-card"" style=""border: 1px solid #ccc; padding: 10px; margin: 10px 0;"">
    <h3 style=""color: #2b5797;"">Клієнт: {safeClientName}</h3>
    <p class=""comment"">{safeComment}</p>
    <small>Статус: Безпечно екрановано за стандартом Anti-XSS</small>
</div>";
        return Task.FromResult(html);
    }

    #endregion

    #region A1.4: Mail Header Injection (SMTP CRLF)

    /// <summary>
    /// ВРАЗЛИВИЙ МЕТОД: Формування поштових заголовків із несанітизованого поля вводу.
    /// Якщо адреса або тема містять %0d%0a (\r\n), зловмисник впроваджує нові заголовки (наприклад, Bcc: director@tntu.edu.ua).
    /// </summary>
    public Task<string> SendNotificationVulnerableSmtpAsync(MailHeaderInjectionRequest request)
    {
        // Демонстрація сирого пакету SMTP протоколу
        var rawSmtpMessage = 
$"MAIL FROM: <no-reply@techfix.tntu.edu.ua>\r\n" +
$"RCPT TO: <{request.ToEmail}>\r\n" +
$"DATA\r\n" +
$"From: TechFix Service <support@techfix.tntu.edu.ua>\r\n" +
$"To: {request.ToEmail}\r\n" +
$"Subject: {request.Subject}\r\n\r\n" +
$"{request.MessageBody}\r\n.\r\n";

        return Task.FromResult($"[VULNERABLE SMTP SERVER LOG] RAW PROTOCOL PACKET TRANSMITTED:\n{rawSmtpMessage}");
    }

    /// <summary>
    /// БЕЗПЕЧНИЙ МЕТОД: Валідація на символи переведення рядка \r (\x0D) та \n (\x0A) у поштових заголовках.
    /// </summary>
    public Task<string> SendNotificationSecureSmtpAsync(MailHeaderInjectionRequest request)
    {
        if (request.ToEmail.Contains('\r') || request.ToEmail.Contains('\n') ||
            request.Subject.Contains('\r') || request.Subject.Contains('\n'))
        {
            return Task.FromResult("Security Alert: CRLF Injection detected in email headers (\\r or \\n found). Message rejected.");
        }

        // Сувора перевірка синтаксису адреси
        var isEmailValid = Regex.IsMatch(request.ToEmail, @"^[^@\s]+@[^@\s]+\.[^@\s]+$");
        if (!isEmailValid)
        {
            return Task.FromResult("Security Alert: Invalid recipient email syntax.");
        }

        var safeSmtpLog = 
$"[SECURE SMTP CLIENT] Dispatched successfully to validated recipient <{request.ToEmail}> with Subject '{request.Subject}'. Headers sanitized against CRLF.";
        return Task.FromResult(safeSmtpLog);
    }

    #endregion
}
