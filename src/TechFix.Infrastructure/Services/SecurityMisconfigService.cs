using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using TechFix.Application.DTOs;
using TechFix.Application.Interfaces;
using TechFix.Infrastructure.Persistence;

namespace TechFix.Infrastructure.Services;

public class SecurityMisconfigService : ISecurityMisconfigService
{
    private readonly TechFixDbContext _context;

    public SecurityMisconfigService(TechFixDbContext context)
    {
        _context = context;
    }

    // ==========================================
    // TASK 1: UNHANDLED ERRORS & STACK TRACES
    // ==========================================

    public Task<object> TriggerErrorVulnerableAsync(string trigger)
    {
        // ВРАЗЛИВІСТЬ (CWE-209: Generation of Error Message Containing Sensitive Information)
        // Необроблений виняток викидає стек викликів, локальні шляхи до файлів C:\OneDrive\...
        // та внутрішній текст SQL запиту безпосередньо у відповідь клієнту
        if (trigger == "sql_fail")
        {
            throw new InvalidOperationException(
                "Database Query Failure: Fatal error in TechFixDbContext.Parts.FromSqlRaw(\"SELECT * FROM NonExistentTable_Production\"). " +
                "Connection String: Data Source=C:\\OneDrive\\ТНТУ ПУЛЮЯ\\3 семестр\\techfix_security.db;Mode=ReadWrite; " +
                "Internal StackTrace: at TechFix.Infrastructure.Services.SecurityMisconfigService.TriggerErrorVulnerableAsync line 42.");
        }

        if (trigger == "null_ref")
        {
            string? nullObj = null;
            var len = nullObj!.Length; // NullReferenceException
        }

        return Task.FromResult<object>(new { Message = "Помилку не викликано. Спробуйте trigger=sql_fail або trigger=null_ref." });
    }

    public Task<object> TriggerErrorSecureAsync(string trigger)
    {
        // ЗАХИЩЕНА РЕАЛІЗАЦІЯ (RFC 7807 ProblemDetails + Correlation Trace Identifier)
        // Внутрішні технічні деталі логуються на сервері, а клієнту віддається знеособлений код помилки
        var correlationId = Guid.NewGuid().ToString("N")[..8].ToUpper();

        try
        {
            if (trigger == "sql_fail" || trigger == "null_ref")
            {
                throw new InvalidOperationException("Internal simulation failure");
            }

            return Task.FromResult<object>(new { Success = true, Message = "Операція успішна." });
        }
        catch (Exception)
        {
            // У реальному бекенді тут виконується _logger.LogError(ex, "TraceId: {CorrelationId}", correlationId);
            return Task.FromResult<object>(new
            {
                Type = "https://tools.ietf.org/html/rfc7807",
                Title = "An unexpected error occurred while processing your request.",
                Status = 500,
                IncidentTrackingId = $"ERR-TNTU-{correlationId}",
                UserMessage = "Виникла внутрішня помилка сервера. Будь ласка, повідомте службу підтримки за ідентифікатором інциденту.",
                SecurityPolicy = "Stack trace and sensitive system paths are strictly withheld from client response (CWE-209 Neutralized)."
            });
        }
    }

    // ==========================================
    // TASK 2: EXPOSED BACKUP & SENSITIVE FILES
    // ==========================================

    public Task<BackupDownloadResponseDto> AccessBackupFileVulnerableAsync(string fileName)
    {
        // ВРАЗЛИВІСТЬ (CWE-552: Files or Directories Accessible to External Parties)
        // Дозвіл завантаження резервних копій бази даних, конфігурацій чи сховищ паролів (.bak, .kdbx, .json)
        if (fileName.Contains("techfix_backup") || fileName.Contains(".bak") || fileName.Contains(".kdbx"))
        {
            return Task.FromResult(new BackupDownloadResponseDto
            {
                Success = true,
                FileName = fileName,
                Message = "[КРИТИЧНА ВРАЗЛИВІСТЬ КОНФІГУРАЦІЇ]: Сервер надав прямий публічний доступ до резервної копії файлу (CWE-552)!",
                ContentPreview = "KDBX4_DATABASE_HEADER\nMasterKeyHash: Caoimhe_SupportKeyFile\nEncryptedDatabase: AES256-GCM\n[DATABASE_DUMP_USERS]: admin, student, jerry, support_agent",
                SecurityMode = "Vulnerable (Sensitive File Exposure)"
            });
        }

        return Task.FromResult(new BackupDownloadResponseDto
        {
            Success = false,
            FileName = fileName,
            Message = "Файл не знайдено."
        });
    }

    public Task<BackupDownloadResponseDto> AccessBackupFileSecureAsync(string fileName)
    {
        // ЗАХИЩЕНА РЕАЛІЗАЦІЯ: Чорний список небезпечних розширень та заборона доступу до бекапів
        var blockedExtensions = new[] { ".bak", ".kdbx", ".db", ".sqlite", ".config", ".env", ".json" };
        bool isBlocked = blockedExtensions.Any(ext => fileName.EndsWith(ext, StringComparison.OrdinalIgnoreCase));

        if (isBlocked)
        {
            return Task.FromResult(new BackupDownloadResponseDto
            {
                Success = false,
                FileName = fileName,
                Message = "Security Alert: 403 Forbidden. Доступ до резервних копій, конфігурацій та баз даних суворо заборонено політикою веб-сервера.",
                SecurityMode = "Secure (Static Files Hardened)"
            });
        }

        return Task.FromResult(new BackupDownloadResponseDto
        {
            Success = false,
            FileName = fileName,
            Message = "Доступ заблоковано."
        });
    }

    // ==========================================
    // TASK 3: DEVELOPER COMMENTS & SECRETS LEAK
    // ==========================================

    public Task<object> GetSupportCredentialsLeakVulnerableAsync()
    {
        // ВРАЗЛИВІСТЬ (CWE-615: Inclusion of Sensitive Information in Source Code Comments)
        // Залишені коментарі розробників у JavaScript/HTML, які розкривають облікові дані підтримки
        return Task.FromResult<object>(new
        {
            ClientScript = "https://techfix.tntu.edu.ua/assets/js/support-bundle.js",
            ExposedHtmlComments = new[]
            {
                "<!-- @echipa de suport: Secretul nostru comun este încă Caoimhe cu parola de master gol! -->",
                "// TODO: Remove before production: support_agent / KlintIstvud3130 (Station: TNTU-122)",
                "/* Internal note: Diagnostic endpoint accessible at /api/A5_AccessControl/hidden-admin-data */"
            },
            Vulnerability = "Коментарі розробників у клієнтських скриптах розкривають паролі та внутрішні алгоритми (Juice Shop / WebGoat pattern)."
        });
    }

    public Task<object> GetSupportCredentialsLeakSecureAsync()
    {
        // ЗАХИЩЕНА РЕАЛІЗАЦІЯ: Мініфікація, обфускація та автоматичне очищення коментарів у CI/CD
        return Task.FromResult<object>(new
        {
            ClientScript = "https://techfix.tntu.edu.ua/assets/js/support-bundle.min.js",
            CommentsStatus = "Cleaned & Stripped during Production Build Pipeline",
            SecretsScanning = "GitHub Secret Scanning & SonarQube verified 0 hardcoded comments/credentials.",
            SecurityMode = "Secure (Automated Secret Hygiene)"
        });
    }

    // ==========================================
    // TASK 4: SECURITY HEADERS & CORS AUDIT
    // ==========================================

    public List<SecurityHeadersAuditDto> AuditSecurityHeaders(bool secureMode)
    {
        var list = new List<SecurityHeadersAuditDto>();

        if (!secureMode)
        {
            list.Add(new SecurityHeadersAuditDto
            {
                HeaderName = "Server",
                Value = "Kestrel / Microsoft-HTTPAPI/2.0",
                Status = "Vulnerable (Server Fingerprint Exposed)",
                Recommendation = "Видалити заголовок Server через options.AddServerHeader = false."
            });
            list.Add(new SecurityHeadersAuditDto
            {
                HeaderName = "X-Powered-By",
                Value = "ASP.NET Core 10.0",
                Status = "Vulnerable (Technology Stack Exposed)",
                Recommendation = "Приховати версію фреймворку у HTTP-пакетах."
            });
            list.Add(new SecurityHeadersAuditDto
            {
                HeaderName = "X-Frame-Options",
                Value = "MISSING",
                Status = "Vulnerable (Clickjacking Possible)",
                Recommendation = "Встановити X-Frame-Options: DENY або SAMEORIGIN."
            });
            list.Add(new SecurityHeadersAuditDto
            {
                HeaderName = "X-Content-Type-Options",
                Value = "MISSING",
                Status = "Vulnerable (MIME-Sniffing Attack)",
                Recommendation = "Встановити X-Content-Type-Options: nosniff."
            });
            list.Add(new SecurityHeadersAuditDto
            {
                HeaderName = "Content-Security-Policy (CSP)",
                Value = "MISSING",
                Status = "Vulnerable (XSS / Data Injection)",
                Recommendation = "Встановити сувору політику default-src 'self'."
            });
            list.Add(new SecurityHeadersAuditDto
            {
                HeaderName = "Access-Control-Allow-Origin (CORS)",
                Value = "* (Wildcard with Credentials)",
                Status = "Vulnerable (Overly Permissive CORS - CWE-942)",
                Recommendation = "Вказати точний білий список довірених доменів."
            });
        }
        else
        {
            list.Add(new SecurityHeadersAuditDto
            {
                HeaderName = "Server",
                Value = "[REMOVED]",
                Status = "Secure",
                Recommendation = "Інформація про веб-сервер прихована."
            });
            list.Add(new SecurityHeadersAuditDto
            {
                HeaderName = "X-Frame-Options",
                Value = "DENY",
                Status = "Secure",
                Recommendation = "Захист від атак клікджекінгу (Clickjacking) активовано."
            });
            list.Add(new SecurityHeadersAuditDto
            {
                HeaderName = "X-Content-Type-Options",
                Value = "nosniff",
                Status = "Secure",
                Recommendation = "Браузеру заборонено виконувати MIME-sniffing."
            });
            list.Add(new SecurityHeadersAuditDto
            {
                HeaderName = "Content-Security-Policy",
                Value = "default-src 'self'; script-src 'self'; frame-ancestors 'none';",
                Status = "Secure",
                Recommendation = "Повна ізоляція виконання небезпечних скриптів."
            });
            list.Add(new SecurityHeadersAuditDto
            {
                HeaderName = "Strict-Transport-Security (HSTS)",
                Value = "max-age=31536000; includeSubDomains",
                Status = "Secure",
                Recommendation = "Примусове використання захищеного HTTPS з'єднання."
            });
        }

        return list;
    }
}
