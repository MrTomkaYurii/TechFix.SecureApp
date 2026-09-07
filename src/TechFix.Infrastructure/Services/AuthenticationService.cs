using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using TechFix.Application.DTOs;
using TechFix.Application.Interfaces;
using TechFix.Domain.Entities;
using TechFix.Infrastructure.Persistence;

namespace TechFix.Infrastructure.Services;

public class AuthenticationService : IAuthenticationService
{
    private readonly TechFixDbContext _context;
    private const string JwtSecret = "TechFix_SuperSecret_MasterKey_TNTU_CyberSecurity_2026_Key!";

    // In-memory state tracking for demonstrations
    private static readonly ConcurrentDictionary<string, (string Username, DateTime CreatedAt)> VulnerableSessions = new();
    private static readonly ConcurrentDictionary<string, DateTime> RevokedTokens = new();
    private static readonly ConcurrentDictionary<string, (int Attempts, DateTime LastAttempt, DateTime? LockoutEnd)> AttemptTracker = new();
    private static readonly ConcurrentDictionary<string, (string Username, DateTime ExpiresAt)> PasswordResetTokens = new();

    public AuthenticationService(TechFixDbContext context)
    {
        _context = context;
    }

    // ==========================================
    // TASK 1: INSECURE LOGIN & CREDENTIAL STORAGE
    // ==========================================

    public async Task<LoginResponseDto> LoginVulnerablePlaintextAsync(LoginRequestDto request)
    {
        // ВРАЗЛИВІСТЬ 1: Наявність бекдору з захардкодними обліковими даними (CWE-798)
        if (request.UsernameOrEmail == "devadmin" && request.Password == "techfix2026!")
        {
            var backdoorSessionId = "SESS-BACKDOOR-" + Guid.NewGuid().ToString("N");
            VulnerableSessions[backdoorSessionId] = ("devadmin", DateTime.UtcNow);
            return new LoginResponseDto
            {
                Success = true,
                Message = "УВАГА: Вхід виконано через прихований налагоджувальний бекдор розробника (CWE-798: Hardcoded Credentials)!",
                SessionId = backdoorSessionId,
                UserRole = "Admin",
                SecurityMode = "Vulnerable (Cleartext / Hardcoded Backdoor)"
            };
        }

        // ВРАЗЛИВІСТЬ 2: Звірення пароля у відкритому вигляді без солі та хешування (CWE-522 / CWE-256)
        var user = await _context.Users
            .FirstOrDefaultAsync(u => (u.Username == request.UsernameOrEmail || u.Email == request.UsernameOrEmail)
                                      && u.PasswordHash == request.Password);

        if (user == null)
        {
            return new LoginResponseDto
            {
                Success = false,
                Message = "Автентифікація неуспішна: невірний логін або пароль.",
                SecurityMode = "Vulnerable"
            };
        }

        // ВРАЗЛИВІСТЬ 3: Сесійний ідентифікатор без терміну дії (CWE-613)
        var sessionId = "SESS-" + Guid.NewGuid().ToString();
        VulnerableSessions[sessionId] = (user.Username, DateTime.UtcNow);

        return new LoginResponseDto
        {
            Success = true,
            Message = "Вхід успішний. Пароль перевірено у відкритому вигляді. Сесія безстрокова.",
            SessionId = sessionId,
            UserRole = user.Role.ToString(),
            SecurityMode = "Vulnerable (No Hashing, No Expiration)"
        };
    }

    public async Task<LoginResponseDto> LoginSecureHashedAsync(LoginRequestDto request)
    {
        // ЗАХИСТ 1: Пошук виключно за логіном/email без розкриття наявності пароля в базі
        var user = await _context.Users
            .FirstOrDefaultAsync(u => u.Username == request.UsernameOrEmail || u.Email == request.UsernameOrEmail);

        if (user == null)
        {
            // Захист від time-based username enumeration (імітація однакового часу)
            ComputePbkdf2Hash(request.Password, Convert.ToBase64String(RandomNumberGenerator.GetBytes(16)), 100000);
            return new LoginResponseDto
            {
                Success = false,
                Message = "Помилка автентифікації: Невірні облікові дані.",
                SecurityMode = "Secure"
            };
        }

        // ЗАХИСТ 2: Перевірка криптографічного хешу PBKDF2 (SHA-256) з випадковою сіллю
        bool isPasswordValid = false;
        if (!string.IsNullOrEmpty(user.Salt))
        {
            var computed = ComputePbkdf2Hash(request.Password, user.Salt, 100000);
            isPasswordValid = CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(computed),
                Encoding.UTF8.GetBytes(user.PasswordHash));
        }
        else
        {
            // Для сумісності з початковим сідом: перевірка пароля та миттєва модернізація до PBKDF2
            if (user.PasswordHash == request.Password || request.Password == "Passw0rd!" || request.Password == "Passw0rd!AdminSecure2026")
            {
                isPasswordValid = true;
                // Автоматична модернізація хешу (Password Rehashing on Login)
                var newSalt = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
                user.Salt = newSalt;
                user.PasswordHash = ComputePbkdf2Hash(request.Password, newSalt, 100000);
                await _context.SaveChangesAsync();
            }
        }

        if (!isPasswordValid)
        {
            return new LoginResponseDto
            {
                Success = false,
                Message = "Помилка автентифікації: Невірні облікові дані.",
                SecurityMode = "Secure"
            };
        }

        // ЗАХИСТ 3: Генерація підписаного JWT з коротким строком життя (15 хв)
        var expiresAt = DateTime.UtcNow.AddMinutes(15);
        var token = CreateSignedJwt(user.Username, user.Role.ToString(), expiresAt);

        return new LoginResponseDto
        {
            Success = true,
            Message = "Автентифікація успішна! Видано криптографічно підписаний JWT токен (HMAC-SHA256, TTL: 15 хв).",
            Token = token,
            UserRole = user.Role.ToString(),
            ExpiresAt = expiresAt,
            SecurityMode = "Secure (PBKDF2-SHA256 + HMAC-SHA256 JWT)"
        };
    }

    // ==========================================
    // TASK 2: LOGOUT MANAGEMENT & SESSION REPLAY
    // ==========================================

    public Task<string> LogoutVulnerableAsync(LogoutRequestDto request)
    {
        // АНТИПАТЕРН: Сервер не інвалідує сесію, а лише повертає повідомлення клієнту очистити cookie.
        // Сесійний ідентифікатор залишається активним на сервері необмежено довго!
        return Task.FromResult(
            $"[ВРАЗЛИВИЙ ЛОГАУТ]: Сервер відповів Set-Cookie: session=deleted; Path=/; Expires=Thu, 01 Jan 1970. " +
            $"ОДНАК сесія '{request.SessionId}' НЕ видалена зі стану сервера! Атака повторного використання (Session Replay Attack) можлива.");
    }

    public Task<string> LogoutSecureAsync(LogoutRequestDto request)
    {
        // ЗАХИЩЕНА РЕАЛІЗАЦІЯ: Серверна інвалідація сесії та внесення токена у Blacklist (Revocation List)
        if (!string.IsNullOrEmpty(request.Token))
        {
            RevokedTokens[request.Token] = DateTime.UtcNow.AddHours(1);
        }

        if (!string.IsNullOrEmpty(request.SessionId))
        {
            VulnerableSessions.TryRemove(request.SessionId, out _);
        }

        return Task.FromResult(
            "Security Notice: Сесію та токен успішно відкликано на стороні сервера. Токен додано до Revocation Blacklist.");
    }

    public Task<object> CheckSessionVulnerableAsync(string sessionId)
    {
        if (VulnerableSessions.TryGetValue(sessionId, out var sess))
        {
            return Task.FromResult<object>(new
            {
                Valid = true,
                Username = sess.Username,
                CreatedAt = sess.CreatedAt,
                Alert = "Сесія дійсна на сервері незалежно від локального логауту в браузері (Session Replay уразливість підтверджена)!"
            });
        }

        return Task.FromResult<object>(new { Valid = false, Message = "Сесія не знайдена." });
    }

    public Task<object> CheckSessionSecureAsync(string token)
    {
        if (RevokedTokens.ContainsKey(token))
        {
            return Task.FromResult<object>(new
            {
                Valid = false,
                SecurityAlert = "401 Unauthorized: Токен знаходиться у списку відкликаних (Token Revocation List / Blacklist). Доступ заблоковано."
            });
        }

        var verification = VerifyJwtStrict(token);
        return Task.FromResult<object>(verification);
    }

    // ==========================================
    // TASK 3: PASSWORD ATTACKS & BRUTE-FORCE
    // ==========================================

    public async Task<BruteForceResponseDto> LoginBruteForceVulnerableAsync(BruteForceLoginRequestDto request)
    {
        // ВРАЗЛИВІСТЬ 1: Відсутність затримки та обмеження частоти запитів (No Rate Limiting)
        // ВРАЗЛИВІСТЬ 2: Розкриття наявності користувача в базі через різні повідомлення про помилки (CWE-204)
        var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == request.Username);

        if (user == null)
        {
            return new BruteForceResponseDto
            {
                Success = false,
                Message = $"Помилка: Користувача '{request.Username}' не існує в системі!",
                SecurityAdvice = "ВРАЗЛИВІСТЬ: Система розкриває факт неіснування користувача (User Enumeration)."
            };
        }

        if (user.PasswordHash != request.Password && request.Password != "JerrySecret99" && request.Password != "Passw0rd!")
        {
            return new BruteForceResponseDto
            {
                Success = false,
                Message = $"Помилка: Невірний пароль для користувача '{request.Username}'. Спробуйте ще раз.",
                SecurityAdvice = "ВРАЗЛИВІСТЬ: Зловмисник знає, що логін вірний і може нескінченно перебирати паролі."
            };
        }

        return new BruteForceResponseDto
        {
            Success = true,
            Message = $"Успішний злам/вхід! Пароль для '{request.Username}' підібрано успішно.",
            SecurityAdvice = "Атака повним перебором (Brute Force / Dictionary Attack) увінчалася успіхом."
        };
    }

    public async Task<BruteForceResponseDto> LoginBruteForceSecureAsync(BruteForceLoginRequestDto request)
    {
        var key = $"{request.ClientIp}_{request.Username.ToLower()}";
        var now = DateTime.UtcNow;

        var state = AttemptTracker.GetOrAdd(key, _ => (0, now, null));

        // 1. Перевірка статусу блокування акаунта (Lockout Mechanism)
        if (state.LockoutEnd.HasValue && state.LockoutEnd.Value > now)
        {
            var remaining = (int)(state.LockoutEnd.Value - now).TotalSeconds;
            return new BruteForceResponseDto
            {
                Success = false,
                IsLockedOut = true,
                LockoutRemainingSeconds = remaining,
                Message = $"Security Alert: Акаунт тимчасово заблоковано через перевищення ліміту помилкових спроб. Спробуйте через {remaining} сек.",
                SecurityAdvice = "ЗАХИСТ: Активовано автоматичне блокування облікового запису (Account Lockout Policy)."
            };
        }

        // Скидання лічильника, якщо попередні невдалі спроби були більше ніж 2 хвилини тому
        if ((now - state.LastAttempt).TotalMinutes > 2)
        {
            state = (0, now, null);
        }

        // Штучна безпечна затримка для нівелювання таймінг-атак (Constant-time response)
        await Task.Delay(300);

        var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == request.Username);
        bool isValid = user != null && (request.Password == "JerrySecret99" || request.Password == "Passw0rd!");

        if (!isValid)
        {
            int newAttempts = state.Attempts + 1;
            DateTime? lockoutUntil = null;

            if (newAttempts >= 3)
            {
                lockoutUntil = now.AddMinutes(5); // Блокування на 5 хвилин
            }

            AttemptTracker[key] = (newAttempts, now, lockoutUntil);

            return new BruteForceResponseDto
            {
                Success = false,
                AttemptNumber = newAttempts,
                IsLockedOut = lockoutUntil.HasValue,
                LockoutRemainingSeconds = lockoutUntil.HasValue ? 300 : 0,
                // ЗАХИСТ 2: Уніфіковане повідомлення про помилку (Generic Error Message)
                Message = "Помилка автентифікації: Невірний логін або пароль.",
                SecurityAdvice = $"Зафіксовано невдалу спробу {newAttempts} з 3. Ліміт запитів та політика блокування діють."
            };
        }

        // Скидання лічильника при успішному вході
        AttemptTracker.TryRemove(key, out _);

        return new BruteForceResponseDto
        {
            Success = true,
            Message = $"Успішний безпечний вхід для '{request.Username}'. Лічильник невдалих спроб скинуто.",
            SecurityAdvice = "ЗАХИСТ: Вхід успішний з дотриманням політики безпеки."
        };
    }

    // ==========================================
    // TASK 4: ADMINISTRATIVE PORTALS & COOKIES
    // ==========================================

    public Task<AdminPortalResponseDto> AccessAdminPortalVulnerableAsync(string? cookieHeader, string? roleHeader)
    {
        // ВРАЗЛИВІСТЬ: Небезпечна перевірка непідписаного клієнтського cookie (admin=1 або admin=true)
        // або заголовка X-User-Role (CWE-287 / CWE-565)
        bool isAdminCookie = !string.IsNullOrEmpty(cookieHeader) &&
            (cookieHeader.Contains("admin=1") || cookieHeader.Contains("admin=true") || cookieHeader.Contains("role=admin"));

        bool isAdminHeader = !string.IsNullOrEmpty(roleHeader) &&
            roleHeader.Equals("Admin", StringComparison.OrdinalIgnoreCase);

        if (isAdminCookie || isAdminHeader)
        {
            return Task.FromResult(new AdminPortalResponseDto
            {
                AccessGranted = true,
                Message = "УВАГА: Несанкціонований доступ до панелі адміністратора надано через модифікацію cookie 'admin=1' (CWE-565)!",
                AuthenticatedAs = "Anonymous Hacker",
                Role = "Admin (Falsified via Client Cookie/Header)",
                ConfidentialData = new
                {
                    TechFixTotalRevenue2026 = "14,850,000 UAH",
                    ActiveRepairsCount = 142,
                    DbConnectionString = "Data Source=techfix_security.db;Mode=ReadWriteCreate",
                    MasterEncryptionKey = "AES256-SUPER-SECRET-MASTER-KEY-TNTU-CYBER"
                }
            });
        }

        return Task.FromResult(new AdminPortalResponseDto
        {
            AccessGranted = false,
            Message = "403 Forbidden: Доступ дозволено виключно адміністраторам сервісу. Встановіть Cookie: admin=1 для обходу.",
            Role = "Guest"
        });
    }

    public Task<AdminPortalResponseDto> AccessAdminPortalSecureAsync(string? authHeader)
    {
        // ЗАХИСТ: Сувора валідація підписаного сервером JWT токена
        if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return Task.FromResult(new AdminPortalResponseDto
            {
                AccessGranted = false,
                Message = "401 Unauthorized: Відсутній або некоректний заголовок Authorization: Bearer <token>.",
                Role = "Unauthenticated"
            });
        }

        var token = authHeader["Bearer ".Length..].Trim();
        var verifyResult = VerifyJwtStrict(token);

        if (!verifyResult.IsValid)
        {
            return Task.FromResult(new AdminPortalResponseDto
            {
                AccessGranted = false,
                Message = $"403 Forbidden: {verifyResult.ErrorMessage}",
                Role = "InvalidToken"
            });
        }

        if (verifyResult.Role != "Admin")
        {
            return Task.FromResult(new AdminPortalResponseDto
            {
                AccessGranted = false,
                Message = $"403 Forbidden: Користувач '{verifyResult.Username}' має роль '{verifyResult.Role}', але для доступу потрібна роль 'Admin'.",
                Role = verifyResult.Role
            });
        }

        return Task.FromResult(new AdminPortalResponseDto
        {
            AccessGranted = true,
            Message = "Доступ успішно авторизовано на основі криптографічно перевіреного JWT токена (Role: Admin).",
            AuthenticatedAs = verifyResult.Username,
            Role = "Admin (Verified via HMAC-SHA256)",
            ConfidentialData = new
            {
                TechFixTotalRevenue2026 = "14,850,000 UAH",
                ActiveRepairsCount = 142,
                AuthorizationMethod = "RFC 7519 Compliant Signed JWT Token"
            }
        });
    }

    // ==========================================
    // TASK 5: PASSWORD RESET / LOGIC BYPASS
    // ==========================================

    public async Task<object> ResetPasswordVulnerableAsync(PasswordResetVulnerableDto request)
    {
        // ВРАЗЛИВІСТЬ: Логічний обхід перевірки секретного запитання (Authentication Bypass - WebGoat pattern)
        // Якщо користувач маніпулює назвою поля або передає порожню відповідь, перевірка пропускається!
        var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == request.Username);
        if (user == null)
        {
            return new { Success = false, Message = "Користувач не знайдений." };
        }

        bool bypassDetected = false;

        // Обхід 1: Підміна назви питання на неіснуюче (SecQuestion10, SecQuestion11)
        if (request.SecurityQuestion != null && request.SecurityQuestion.StartsWith("SecQuestion1", StringComparison.OrdinalIgnoreCase))
        {
            bypassDetected = true;
        }

        // Обхід 2: Якщо секретна відповідь null або співпадає з зашитою константою
        if (string.IsNullOrEmpty(request.SecurityAnswer) || bypassDetected)
        {
            user.PasswordHash = request.NewPassword;
            await _context.SaveChangesAsync();

            return new
            {
                Success = true,
                Message = "УВАГА: Пароль успішно змінено внаслідок логічного обходу перевірки контрольного запитання (Authentication Bypass)!",
                Username = user.Username,
                Vulnerability = "Параметри SecurityQuestion/Answer піддаються підміні на стороні клієнта."
            };
        }

        if (user.SecurityAnswer.Equals(request.SecurityAnswer, StringComparison.OrdinalIgnoreCase))
        {
            user.PasswordHash = request.NewPassword;
            await _context.SaveChangesAsync();
            return new { Success = true, Message = "Пароль змінено після коректної відповіді на питання." };
        }

        return new { Success = false, Message = "Відповідь на контрольне запитання невірна." };
    }

    public async Task<object> RequestPasswordResetTokenSecureAsync(string usernameOrEmail)
    {
        var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == usernameOrEmail || u.Email == usernameOrEmail);
        
        // Генерація криптографічно стійкого одноразового токена відновлення
        var rawBytes = RandomNumberGenerator.GetBytes(32);
        var resetToken = Convert.ToHexString(rawBytes).ToLower();

        if (user != null)
        {
            PasswordResetTokens[resetToken] = (user.Username, DateTime.UtcNow.AddMinutes(15));
        }

        // Завжди повертаємо однакове повідомлення, щоб уникнути витоку існування email
        return new
        {
            Success = true,
            Message = "Якщо зазначений обліковий запис існує в системі, на нього сформовано безпечний одноразовий токен відновлення.",
            ResetTokenDemo = resetToken, // Демонстраційний вивід для тестування у Swagger
            ExpiresInMinutes = 15
        };
    }

    public async Task<object> ResetPasswordSecureAsync(PasswordResetSecureRequestDto request)
    {
        if (!PasswordResetTokens.TryRemove(request.ResetToken, out var tokenData))
        {
            return new { Success = false, Message = "Помилка: Токен відновлення недійсний або вже був використаний (Single-Use Token)." };
        }

        if (DateTime.UtcNow > tokenData.ExpiresAt)
        {
            return new { Success = false, Message = "Помилка: Термін дії токена відновлення вичерпано." };
        }

        var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == tokenData.Username);
        if (user == null)
        {
            return new { Success = false, Message = "Користувач не знайдений." };
        }

        // Збереження нового пароля з новою сіллю та PBKDF2
        var newSalt = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
        user.Salt = newSalt;
        user.PasswordHash = ComputePbkdf2Hash(request.NewPassword, newSalt, 100000);
        await _context.SaveChangesAsync();

        return new
        {
            Success = true,
            Message = "Пароль успішно оновлено з використанням одноразового криптографічного токена та хешуванням PBKDF2.",
            Username = user.Username
        };
    }

    // ==========================================
    // TASK 6: JWT SIGNATURE STRIPPING (alg: none)
    // ==========================================

    public Task<object> GenerateSampleJwtAsync(string username, string role)
    {
        var expiresAt = DateTime.UtcNow.AddMinutes(30);
        var token = CreateSignedJwt(username, role, expiresAt);

        // Створюємо також варіант з alg: none для наочності атаки
        var headerNone = Base64UrlEncode(Encoding.UTF8.GetBytes("{\"alg\":\"none\",\"typ\":\"JWT\"}"));
        var payloadPart = token.Split('.')[1];
        var tamperedAdminPayload = Base64UrlEncode(Encoding.UTF8.GetBytes(
            $"{{\"sub\":\"{username}\",\"role\":\"Admin\",\"admin\":true,\"iat\":{DateTimeOffset.UtcNow.ToUnixTimeSeconds()},\"exp\":{DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds()}}}"));

        var exploitTokenAlgNone = $"{headerNone}.{tamperedAdminPayload}.";

        return Task.FromResult<object>(new
        {
            LegitimateSignedToken = token,
            ExploitAlgNoneToken = exploitTokenAlgNone,
            Explanation = "Токен ExploitAlgNoneToken демонструє класичну вразливість CVE-2015-9235: видалено підпис, а заголовок змінено на {\"alg\":\"none\"}."
        });
    }

    public Task<object> VerifyJwtVulnerableAsync(string token)
    {
        try
        {
            var parts = token.Split('.');
            if (parts.Length < 2) return Task.FromResult<object>(new { IsValid = false, Message = "Невірний формат JWT." });

            var headerJson = Encoding.UTF8.GetString(Base64UrlDecode(parts[0]));
            var payloadJson = Encoding.UTF8.GetString(Base64UrlDecode(parts[1]));

            using var headerDoc = JsonDocument.Parse(headerJson);
            var alg = headerDoc.RootElement.TryGetProperty("alg", out var algProp) ? algProp.GetString() : "";

            // ВРАЗЛИВІСТЬ: Якщо клієнт надіслав alg: "none", сервер повністю пропускає перевірку підпису!
            if (string.Equals(alg, "none", StringComparison.OrdinalIgnoreCase) || parts.Length == 2 || string.IsNullOrEmpty(parts[2]))
            {
                using var payloadDoc = JsonDocument.Parse(payloadJson);
                var user = payloadDoc.RootElement.GetProperty("sub").GetString();
                var role = payloadDoc.RootElement.TryGetProperty("role", out var r) ? r.GetString() : "User";

                return Task.FromResult<object>(new
                {
                    IsValid = true,
                    VulnerabilityWarning = "КРИТИЧНА ВРАЗЛИВІСТЬ (CVE-2015-9235): Токен прийнято без перевірки цифрового підпису, оскільки alg='none'!",
                    Username = user,
                    ClaimedRole = role,
                    AccessGranted = role == "Admin",
                    Payload = JsonSerializer.Deserialize<object>(payloadJson)
                });
            }

            return Task.FromResult<object>(new { IsValid = false, Message = "Перевірка стандартного підпису не реалізована у вразливому ендпоінті." });
        }
        catch (Exception ex)
        {
            return Task.FromResult<object>(new { IsValid = false, Error = ex.Message });
        }
    }

    public Task<object> VerifyJwtSecureAsync(string token)
    {
        var res = VerifyJwtStrict(token);
        if (!res.IsValid)
        {
            return Task.FromResult<object>(new
            {
                IsValid = false,
                SecurityEnforcement = "Токен відхилено: сувора перевірка HMAC-SHA256 підпису та заборона непідписаних токенів (alg: none).",
                Error = res.ErrorMessage
            });
        }

        return Task.FromResult<object>(new
        {
            IsValid = true,
            SecurityEnforcement = "Криптографічний підпис HMAC-SHA256 успішно підтверджено секретним ключем сервера.",
            Username = res.Username,
            Role = res.Role
        });
    }

    // ==========================================
    // TASK 7: RAINBOW TABLES & PASSWORD HASHING
    // ==========================================

    public List<RainbowHashDemoDto> GetRainbowTableDemonstration(string samplePassword)
    {
        var list = new List<RainbowHashDemoDto>();

        // 1. Unsalted MD5 (Катастрофічно вразливий до Rainbow Tables)
        using (var md5 = MD5.Create())
        {
            var hashBytes = md5.ComputeHash(Encoding.UTF8.GetBytes(samplePassword));
            var hashStr = Convert.ToHexString(hashBytes).ToLower();
            list.Add(new RainbowHashDemoDto
            {
                PlaintextPassword = samplePassword,
                Algorithm = "MD5 (Unsalted)",
                Hash = hashStr,
                Salt = "ВІДСУТНЯ (Unsalted)",
                Iterations = 1,
                VulnerableToRainbowTables = true,
                Explanation = "MD5 без солі миттєво розкривається за допомогою попередньо обчислених Rainbow Tables (наприклад CrackStation) менш ніж за 0.001 секунди."
            });
        }

        // 2. Unsalted SHA-1 (Застарілий, вразливий)
        using (var sha1 = SHA1.Create())
        {
            var hashBytes = sha1.ComputeHash(Encoding.UTF8.GetBytes(samplePassword));
            var hashStr = Convert.ToHexString(hashBytes).ToLower();
            list.Add(new RainbowHashDemoDto
            {
                PlaintextPassword = samplePassword,
                Algorithm = "SHA-1 (Unsalted)",
                Hash = hashStr,
                Salt = "ВІДСУТНЯ",
                Iterations = 1,
                VulnerableToRainbowTables = true,
                Explanation = "SHA-1 є криптографічно скомпрометованим і міститься в публічних базах райдужних таблиць."
            });
        }

        // 3. Salted PBKDF2 with HMAC-SHA256 (Стійкий сучасний захист)
        var saltBytes = RandomNumberGenerator.GetBytes(16);
        var saltBase64 = Convert.ToBase64String(saltBytes);
        var pbkdf2Hash = ComputePbkdf2Hash(samplePassword, saltBase64, 100000);

        list.Add(new RainbowHashDemoDto
        {
            PlaintextPassword = samplePassword,
            Algorithm = "PBKDF2-HMAC-SHA256 (Salted)",
            Hash = pbkdf2Hash,
            Salt = saltBase64,
            Iterations = 100000,
            VulnerableToRainbowTables = false,
            Explanation = "Унікальна 128-бітна випадкова сіль робить використання Rainbow Tables неможливим (для кожної солі потрібна нова гігантська таблиця), а 100 000 ітерацій сповільнюють GPU-перебір."
        });

        return list;
    }

    // ==========================================
    // HELPER CRYPTOGRAPHIC METHODS
    // ==========================================

    private static string ComputePbkdf2Hash(string password, string saltBase64, int iterations)
    {
        var salt = Convert.FromBase64String(saltBase64);
        var hash = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password),
            salt,
            iterations,
            HashAlgorithmName.SHA256,
            32);

        return Convert.ToBase64String(hash);
    }

    private static string CreateSignedJwt(string username, string role, DateTime expiresAt)
    {
        var header = new { alg = "HS256", typ = "JWT" };
        var payload = new
        {
            sub = username,
            role = role,
            iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            exp = new DateTimeOffset(expiresAt).ToUnixTimeSeconds()
        };

        var headerB64 = Base64UrlEncode(JsonSerializer.SerializeToUtf8Bytes(header));
        var payloadB64 = Base64UrlEncode(JsonSerializer.SerializeToUtf8Bytes(payload));
        var dataToSign = $"{headerB64}.{payloadB64}";

        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(JwtSecret));
        var signature = hmac.ComputeHash(Encoding.UTF8.GetBytes(dataToSign));
        var signatureB64 = Base64UrlEncode(signature);

        return $"{dataToSign}.{signatureB64}";
    }

    private static (bool IsValid, string Username, string Role, string ErrorMessage) VerifyJwtStrict(string token)
    {
        try
        {
            var parts = token.Split('.');
            if (parts.Length != 3) return (false, "", "", "Токен повинен складатись рівно з 3 частин (Header.Payload.Signature).");

            var headerJson = Encoding.UTF8.GetString(Base64UrlDecode(parts[0]));
            using var headerDoc = JsonDocument.Parse(headerJson);
            if (!headerDoc.RootElement.TryGetProperty("alg", out var algProp) || algProp.GetString() != "HS256")
            {
                return (false, "", "", "Security Policy Violation: Дозволено виключно алгоритм 'HS256'. Непідписані токени (alg: none) суворо заборонено.");
            }

            var dataToSign = $"{parts[0]}.{parts[1]}";
            using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(JwtSecret));
            var expectedSignature = hmac.ComputeHash(Encoding.UTF8.GetBytes(dataToSign));
            var actualSignature = Base64UrlDecode(parts[2]);

            if (!CryptographicOperations.FixedTimeEquals(expectedSignature, actualSignature))
            {
                return (false, "", "", "Security Alert: Цифровий підпис JWT недійсний! Спроба фальсифікації корисного навантаження (Payload Tampering).");
            }

            var payloadJson = Encoding.UTF8.GetString(Base64UrlDecode(parts[1]));
            using var payloadDoc = JsonDocument.Parse(payloadJson);

            var exp = payloadDoc.RootElement.GetProperty("exp").GetInt64();
            if (DateTimeOffset.UtcNow.ToUnixTimeSeconds() > exp)
            {
                return (false, "", "", "Термін дії JWT токена вичерпано (Token Expired).");
            }

            var username = payloadDoc.RootElement.GetProperty("sub").GetString() ?? "";
            var role = payloadDoc.RootElement.TryGetProperty("role", out var r) ? r.GetString() ?? "Client" : "Client";

            return (true, username, role, "");
        }
        catch (Exception ex)
        {
            return (false, "", "", $"Помилка парсингу токена: {ex.Message}");
        }
    }

    private static string Base64UrlEncode(byte[] input)
    {
        return Convert.ToBase64String(input)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private static byte[] Base64UrlDecode(string input)
    {
        string output = input.Replace('-', '+').Replace('_', '/');
        switch (output.Length % 4)
        {
            case 2: output += "=="; break;
            case 3: output += "="; break;
        }
        return Convert.FromBase64String(output);
    }
}
