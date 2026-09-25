# Module 02: OWASP A2: Broken Authentication & Session Management

> Comprehensive security engineering guide, vulnerability analysis, C# code implementations, and Swagger UI practical walkthrough for TechFix Enterprise (.NET 10).

---


## 1. Мета роботи та вихідні дані

Мета роботи: Поглиблене практичне дослідження векторів компрометації систем ідентифікації та автентифікації користувачів (OWASP Top 10 A2: Broken Authentication / Identification and Authentication Failures). Проєктування та розробка надійних архітектурних механізмів захисту на базі еталонного бекенд-проєкту TechFix Enterprise (.NET 10, Clean Architecture): стійке криптографічне хешування паролів (PBKDF2-SHA256 з унікальною сіллю), політика захисту від перебору та блокування акаунтів (Rate Limiting & Account Lockout), безпечне керування життєвим циклом сесій (Session Revocation / Blacklist), авторизація на основі криптографічно підписаних Claims та запобігання фальсифікації JWT токенів (CVE-2015-9235, alg: none).

Вимоги до проєкту: Забезпечення цілісності та кумулятивності навчального проєкту — код Лабораторної роботи №2 додається до Clean Architecture рішення поряд з результатами Лабораторної роботи №1 без їх перезапису чи модифікації. Кожна робота фіксується окремим ізольованим комітом у системі контролю версій Git.


## 2. Кумулятивний розвиток бекенду TechFix Enterprise та Clean Architecture

Архітектурний підхід: У межах виконання Лабораторної роботи №2 архітектуру інформаційної системи сервісного центру TechFix було розширено підсистемою безпечної автентифікації без видалення або пошкодження кодової бази ін'єкцій (OWASP A1). Нові компоненти суворо дотримуються принципу інверсії залежностей (Dependency Inversion) та розділення відповідальності:


| Рівень Clean Architecture | Проєкт у .NET рішенні | Реалізовані компоненти ЛР2 (OWASP A2) |
| --- | --- | --- |
| Domain | TechFix.Domain | Сутність User (Id, Username, Email, PasswordHash, Salt, Role, SecurityQuestion, SecurityAnswer, CreatedAt). Чисті бізнес-сутності без зовнішніх залежностей. |
| Application | TechFix.Application | Інтерфейс IAuthenticationService, моделі DTO: LoginRequestDto, LogoutRequestDto, BruteForceLoginRequestDto, AdminPortalResponseDto, RainbowHashDemoDto. |
| Infrastructure | TechFix.Infrastructure | Сервіс AuthenticationService: подвійна реалізація (Dual-Mode) — вразливі форми, сесії без терміну дії, alg: none vs стійкий PBKDF2-SHA256, Revocation Blacklist, HMAC-SHA256. |
| WebApi (Presentation) | TechFix.WebApi | Контролер A2_AuthenticationController з 17 ендпоінтами під тегом 'OWASP A2: Broken Authentication'. Реєстрація в DI поруч з A1_InjectionController. |


Ідентифікатор коміту лабораторної роботи №2 у Git: 1861fdf7164998797f7bb159e2172772559b35bc (Повідомлення: feat(lab2): implement OWASP A2 - Broken Authentication (Weak Storage, Session Replay, Brute-Force, Admin Tampering, JWT alg-none, Rainbow Tables) with vulnerable and secure endpoints).


![Рисунок 2.1 — Розділ 'OWASP A2: Broken Authentication' у Swagger UI живого веб-сервера TechFix Enterprise](./screenshots/01_swagger_a2_overview.png)
*Рисунок 2.1 — Розділ 'OWASP A2: Broken Authentication' у Swagger UI живого веб-сервера TechFix Enterprise*


## 3. Практичне дослідження вразливостей, експлуатація та Secure Code Remediation


### 3.1. Небезпечні форми входу та захардкоджені облікові дані (CWE-798, CWE-522)

Опис вразливості: У практиці розробки інформаційних систем розробники іноді залишають приховані діагностичні облікові записи ('бекдори') для швидкого налагодження без авторизації або звіряють паролі у відкритому текстовому вигляді без попереднього гешування. У вразливому ендпоінті /api/A2_Authentication/login/vulnerable реалізовано обидва критичні антипатерни.


**Лістинг 2.1 — Вразливий метод автентифікації з бекдором та відкритим паролем**


```csharp
// [ВРАЗЛИВА РЕАЛІЗАЦІЯ: Infrastructure/Services/AuthenticationService.cs]
public async Task<LoginResponseDto> LoginVulnerablePlaintextAsync(LoginRequestDto request)
{
    // АНТИПАТЕРН 1: Прихований бекдор у коді (CWE-798: Hardcoded Credentials)
    if (request.UsernameOrEmail == "devadmin" && request.Password == "techfix2026!")
    {
        var backdoorSessionId = "SESS-BACKDOOR-" + Guid.NewGuid().ToString("N");
        VulnerableSessions[backdoorSessionId] = ("devadmin", DateTime.UtcNow);
        return new LoginResponseDto
        {
            Success = true,
            Message = "УВАГА: Вхід через прихований бекдор розробника (CWE-798)!",
            SessionId = backdoorSessionId,
            UserRole = "Admin"
        };
    }

    // АНТИПАТЕРН 2: Порівняння паролів у відкритому вигляді без соління та хешування (CWE-522)
    var user = await _context.Users
        .FirstOrDefaultAsync(u => (u.Username == request.UsernameOrEmail || u.Email == request.UsernameOrEmail)
                                  && u.PasswordHash == request.Password);
    // ... видача безстрокової сесії
}
```

Експлуатація: Через Swagger UI надіслано запит з обліковими даними devadmin / techfix2026!. Сервер негайно повернув успішну відповідь з роллю Admin та згенерованим сесійним токеном, підтверджуючи повне несанкціоноване захоплення контролю над системою.


![Рисунок 2.2 — Експлуатація бекдору розробника (devadmin) у Swagger UI з отриманням прав Admin](./screenshots/02_swagger_login_weak_backdoor.png)
*Рисунок 2.2 — Експлуатація бекдору розробника (devadmin) у Swagger UI з отриманням прав Admin*

Root Cause Analysis: Наявність захардкоджених паролів у бінарних файлах дозволяє атакувальникам вилучити їх шляхом реверс-інжинірингу або витоку вихідного коду. Збереження паролів у відкритому вигляді веде до масової компрометації під час першого ж витоку БД.

Secure Code Remediation: Повне видалення будь-яких статичних облікових записів. Паролі користувачів перевіряються виключно через криптографічно стійкий алгоритм уповільненого гешування PBKDF2 (HMAC-SHA256, 100 000 ітерацій, 128-бітна випадкова сіль). Після перевірки клієнту видається підписаний JWT з обмеженим часом життя (15 хвилин).


**Лістинг 2.2 — Захищена автентифікація з PBKDF2-SHA256 та фіксованим часом порівняння**


```csharp
// [ЗАХИЩЕНА РЕАЛІЗАЦІЯ: Infrastructure/Services/AuthenticationService.cs]
public async Task<LoginResponseDto> LoginSecureHashedAsync(LoginRequestDto request)
{
    var user = await _context.Users
        .FirstOrDefaultAsync(u => u.Username == request.UsernameOrEmail || u.Email == request.UsernameOrEmail);

    if (user == null)
    {
        // Захист від Timing Attacks: імітація однакового часу обчислення
        ComputePbkdf2Hash(request.Password, Convert.ToBase64String(RandomNumberGenerator.GetBytes(16)), 100000);
        return new LoginResponseDto { Success = false, Message = "Невірні облікові дані." };
    }

    // Безпечне порівняння гешів за фіксований час (Constant-Time Comparison)
    var computed = ComputePbkdf2Hash(request.Password, user.Salt!, 100000);
    if (!CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(computed), Encoding.UTF8.GetBytes(user.PasswordHash)))
    {
        return new LoginResponseDto { Success = false, Message = "Невірні облікові дані." };
    }

    var expiresAt = DateTime.UtcNow.AddMinutes(15);
    var token = CreateSignedJwt(user.Username, user.Role.ToString(), expiresAt);
    return new LoginResponseDto { Success = true, Token = token, ExpiresAt = expiresAt };
}
```


![Рисунок 2.3 — Успішна захищена автентифікація у Swagger UI з видачею підписаного JWT (HMAC-SHA256, TTL 15 хв)](./screenshots/03_swagger_login_secure_remediation.png)
*Рисунок 2.3 — Успішна захищена автентифікація у Swagger UI з видачею підписаного JWT (HMAC-SHA256, TTL 15 хв)*


### 3.2. Керування виходом із системи та атака повторного використання сесії (Session Replay — CWE-613, CWE-384)

Опис вразливості: Вразливість виникає, коли операція виходу з облікового запису (Logout) зводиться лише до надсилання браузеру інструкції видалити локальний cookie. При цьому на стороні сервера сесійний токен або ідентифікатор сесії НЕ анулюється і продовжує залишатися активним у базі або пам'яті сервера.


**Лістинг 2.3 — Вразливий метод виходу без серверної інвалідації сесії**


```csharp
// Вразливо: клієнтський логаут без серверної інвалідації
public Task<string> LogoutVulnerableAsync(LogoutRequestDto request)
{
    // Сервер повертає успіх, але сесія 'request.SessionId' залишається валідною на сервері!
    return Task.FromResult("Set-Cookie: session=deleted. ОДНАК сесія активна на сервері!");
}
```

Експлуатація: У ході експерименту надіслано запит на логаут сесії SESS-7b2f-48d1-93bb-0294821a. Сервер повідомив про видалення куків. Проте наступний запит до перевірки стану сесії підтвердив, що сесійний ключ активний, тобто зловмисник, перехопивши сесійний токен раніше, може безперешкодно виконувати операції під іменем користувача (Session Replay Attack).


![Рисунок 2.4 — Демонстрація Session Replay у Swagger UI: сесія залишається валідною на сервері після логауту](./screenshots/04_swagger_logout_session_replay.png)
*Рисунок 2.4 — Демонстрація Session Replay у Swagger UI: сесія залишається валідною на сервері після логауту*

Secure Code Remediation: Захист полягає в обов'язковій інвалідації стану на сервері: для сесій — повне видалення запису з активного сховища сесій, для stateless JWT — внесення токена у розподілений Blacklist (Revocation List) до закінчення природного терміну життя токена.


**Лістинг 2.4 — Серверне відкликання токена та занесення у Revocation Blacklist**


```csharp
// [ЗАХИЩЕНА РЕАЛІЗАЦІЯ: Infrastructure/Services/AuthenticationService.cs]
public Task<string> LogoutSecureAsync(LogoutRequestDto request)
{
    // 1. Інвалідація токена у сховищі відкликаних (Token Revocation List)
    if (!string.IsNullOrEmpty(request.Token))
    {
        RevokedTokens[request.Token] = DateTime.UtcNow.AddHours(1);
    }

    // 2. Безповоротне видалення сесії зі стану сервера
    if (!string.IsNullOrEmpty(request.SessionId))
    {
        VulnerableSessions.TryRemove(request.SessionId, out _);
    }

    return Task.FromResult("Сесію та токен успішно відкликано на стороні сервера.");
}
```


![Рисунок 2.5 — Захищений логаут у Swagger UI: серверне внесення токена до списку відкликаних (Revocation)](./screenshots/05_swagger_logout_revocation_secure.png)
*Рисунок 2.5 — Захищений логаут у Swagger UI: серверне внесення токена до списку відкликаних (Revocation)*


### 3.3. Атаки перебором паролів та захист від перебору (Brute Force & User Enumeration — CWE-307, CWE-204)

Опис вразливості: Коли система повертає різні повідомлення для неіснуючого логіна ('Користувача не існує') та невірного пароля ('Невірний пароль для даного користувача'), зловмисник отримує змогу скласти точний словник валідних облікових записів (User Enumeration). Відсутність ліміту запитів дозволяє здійснювати автоматизований підбір зі швидкістю тисяч спроб на секунду.


**Лістинг 2.5 — Вразливий код з розкриттям фактів наявності користувача**


```csharp
// Вразливо: розкриття існування облікового запису та відсутність лімітування
if (user == null)
{
    return new BruteForceResponseDto { Message = $"Користувача '{request.Username}' не існує!" };
}
if (user.PasswordHash != request.Password)
{
    return new BruteForceResponseDto { Message = $"Невірний пароль для користувача '{request.Username}'." };
}
```


![Рисунок 2.6 — Витік інформації про існування облікового запису (User Enumeration) у Swagger UI](./screenshots/06_swagger_bruteforce_enumeration_vulnerable.png)
*Рисунок 2.6 — Витік інформації про існування облікового запису (User Enumeration) у Swagger UI*

Secure Code Remediation: Комплексний захист включає:
1. Уніфікацію відповідей про помилки (Generic Error Message): однаковий рядок 'Помилка: Невірний логін або пароль' у будь-якому випадку.
2. Впровадження політики блокування акаунта (Account Lockout Policy): лічильник невдалих спроб за парою IP_Username. Після 3 невдалих спроб акаунт блокується на 5 хвилин із поверненням HTTP 429 Too Many Requests.
3. Штучна фіксована затримка відповіді (300 мс) для запобігання атакам за часом.


**Лістинг 2.6 — Захищений механізм блокування акаунта після 3 невдалих спроб**


```csharp
// [ЗАХИЩЕНА РЕАЛІЗАЦІЯ: Infrastructure/Services/AuthenticationService.cs]
public async Task<BruteForceResponseDto> LoginBruteForceSecureAsync(BruteForceLoginRequestDto request)
{
    var key = $"{request.ClientIp}_{request.Username.ToLower()}";
    var state = AttemptTracker.GetOrAdd(key, _ => (0, DateTime.UtcNow, null));

    // Перевірка блокування акаунта (Lockout)
    if (state.LockoutEnd.HasValue && state.LockoutEnd.Value > DateTime.UtcNow)
    {
        var remaining = (int)(state.LockoutEnd.Value - DateTime.UtcNow).TotalSeconds;
        return new BruteForceResponseDto
        {
            Success = false,
            IsLockedOut = true,
            LockoutRemainingSeconds = remaining,
            Message = $"Security Alert: Акаунт тимчасово заблоковано. Спробуйте через {remaining} сек."
        };
    }

    await Task.Delay(300); // Constant-time delay
    // Перевірка логіна та пароля...
    // При 3-й невдалій спробі встановлюється LockoutEnd = DateTime.UtcNow.AddMinutes(5)
}
```


![Рисунок 2.7 — Спрацювання політики блокування (HTTP 429 Too Many Requests / Account Lockout) у Swagger UI](./screenshots/07_swagger_bruteforce_lockout_secure.png)
*Рисунок 2.7 — Спрацювання політики блокування (HTTP 429 Too Many Requests / Account Lockout) у Swagger UI*


### 3.4. Адміністративні портали та підміна ідентифікаторів у Cookie (CWE-565, CWE-287)

Опис вразливості: У вразливих системах перевірка привілеїв адміністратора нерідко ґрунтується на наявності простих клієнтських прапорців у HTTP-заголовках або Cookie (наприклад, Cookie: admin=1 або Cookie: role=admin). Оскільки клієнт має повний контроль над своїми запитами, зловмисник може самостійно встановити цей прапорець і отримати доступ до критичних функцій.


**Лістинг 2.7 — Вразлива перевірка ролі за непідписаним клієнтським cookie**


```csharp
// Вразливо: довіра до непідписаного клієнтського cookie
bool isAdminCookie = cookieHeader != null && cookieHeader.Contains("admin=1");
if (isAdminCookie)
{
    // Надання доступу до конфіденційної фінансової звітності та ключів шифрування
    return new AdminPortalResponseDto { AccessGranted = true, Role = "Admin (Falsified via Cookie)" };
}
```

Експлуатація: Під час звернення до ендпоінта /api/A2_Authentication/admin-portal/vulnerable передано заголовок Cookie: admin=1. Сервер надав повний адміністративний доступ та розкрив фінансову виручку (14 850 000 грн) і майстер-ключ шифрування бази даних.


![Рисунок 2.8 — Несанкціонований доступ до панелі адміністратора через маніпуляцію Cookie (admin=1) у Swagger UI](./screenshots/08_swagger_admin_cookie_tampering_vulnerable.png)
*Рисунок 2.8 — Несанкціонований доступ до панелі адміністратора через маніпуляцію Cookie (admin=1) у Swagger UI*

Secure Code Remediation: Захист вимагає повної відмови від довіри до сирих заголовків користувача. Ролі повинні вилучатися виключно з криптографічно підписаних серверним секретним ключем токенів JWT (Bearer Authentication). Будь-яка зміна корисного навантаження призводить до порушення цифрового підпису та негайного блокування запиту з кодом 403 Forbidden.


**Лістинг 2.8 — Захищена авторизація на основі верифікації цифрового підпису JWT**


```csharp
// [ЗАХИЩЕНА РЕАЛІЗАЦІЯ: Infrastructure/Services/AuthenticationService.cs]
public Task<AdminPortalResponseDto> AccessAdminPortalSecureAsync(string? authHeader)
{
    var token = authHeader["Bearer ".Length..].Trim();
    var verifyResult = VerifyJwtStrict(token); // Перевірка HMAC-SHA256 підпису

    if (!verifyResult.IsValid || verifyResult.Role != "Admin")
    {
        return Task.FromResult(new AdminPortalResponseDto
        {
            AccessGranted = false,
            Message = "403 Forbidden: Доступ дозволено виключно за валідним підписаним токеном з роллю Admin."
        });
    }

    return Task.FromResult(new AdminPortalResponseDto { AccessGranted = true, Role = "Admin (Verified via HMAC-SHA256)" });
}
```


![Рисунок 2.9 — Захищений адмін-портал у Swagger UI: успішна авторизація за підписаним токеном](./screenshots/09_swagger_admin_portal_secure_jwt.png)
*Рисунок 2.9 — Захищений адмін-портал у Swagger UI: успішна авторизація за підписаним токеном*


### 3.5. Фальсифікація JWT токенів та атака видалення підпису (alg: none — CVE-2015-9235)

Опис вразливості: Специфікація RFC 7519 передбачає можливість використання алгоритму 'none' для налагоджувальних цілей без цифрового підпису. Якщо бібліотека або власний парсер JWT на бекенді сліпо довіряє полю 'alg' у заголовку токена, зловмисник може взяти легітимний токен, змінити роль на 'Admin', замінити 'alg' на 'none', видалити частину підпису і надіслати підроблений токен серверу. Сервер пропустить верифікацію підпису і надасть максимальні привілеї.


**Лістинг 2.9 — Вразливий парсер JWT, що пропускає перевірку підпису при alg: none**


```csharp
// [ВРАЗЛИВИЙ ПАРСЕР JWT: Infrastructure/Services/AuthenticationService.cs]
var headerJson = Encoding.UTF8.GetString(Base64UrlDecode(parts[0]));
using var headerDoc = JsonDocument.Parse(headerJson);
var alg = headerDoc.RootElement.GetProperty("alg").GetString();

// КРИТИЧНИЙ НЕДОЛІК (CVE-2015-9235): Довіра до заголовка alg: none
if (string.Equals(alg, "none", StringComparison.OrdinalIgnoreCase) || parts.Length == 2 || string.IsNullOrEmpty(parts[2]))
{
    // Сервер пропускає перевірку підпису і сліпо довіряє Claims з Payload!
    return new { IsValid = true, AccessGranted = role == "Admin" };
}
```


![Рисунок 2.10 — Експлуатація вразливості JWT alg: none у Swagger UI з отриманням прав адміністратора](./screenshots/10_swagger_jwt_alg_none_vulnerable.png)
*Рисунок 2.10 — Експлуатація вразливості JWT alg: none у Swagger UI з отриманням прав адміністратора*

Secure Code Remediation: Захист базується на примусовому дотриманні політики безпеки алгоритмів: сервер під час верифікації ДОЗВОЛЯЄ виключно алгоритм 'HS256', ігноруючи значення поля alg з вхідного токена, якщо воно не відповідає білому списку. Крім того, обов'язково перевіряється наявність та валідність цифрового підпису через constant-time порівняння.


**Лістинг 2.10 — Сувора верифікація HMAC-SHA256 підпису та блокування токенів без підпису**


```csharp
// [ЗАХИЩЕНА РЕАЛІЗАЦІЯ: Infrastructure/Services/AuthenticationService.cs]
if (!headerDoc.RootElement.TryGetProperty("alg", out var algProp) || algProp.GetString() != "HS256")
{
    return (false, "", "", "Security Policy Violation: Дозволено виключно алгоритм 'HS256'. alg: none заборонено.");
}

// Обчислення еталонного HMAC-SHA256 підпису на сервері
using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(JwtSecret));
var expectedSignature = hmac.ComputeHash(Encoding.UTF8.GetBytes($"{parts[0]}.{parts[1]}"));
var actualSignature = Base64UrlDecode(parts[2]);

if (!CryptographicOperations.FixedTimeEquals(expectedSignature, actualSignature))
{
    return (false, "", "", "Security Alert: Цифровий підпис JWT недійсний!");
}
```


![Рисунок 2.11 — Блокування атаки alg: none у захищеному ендпоінті Swagger UI з генерацією Security Policy Violation](./screenshots/11_swagger_jwt_signature_secure.png)
*Рисунок 2.11 — Блокування атаки alg: none у захищеному ендпоінті Swagger UI з генерацією Security Policy Violation*


### 3.6. Дослідження криптографічної стійкості паролів: райдужні таблиці (Rainbow Tables — CWE-328) проти PBKDF2

Опис загрози: Швидкі односпрямовані геш-функції загального призначення (MD5, SHA-1, SHA-256) проєктувалися для перевірки цілісності файлів і виконуються на сучасних GPU зі швидкістю понад 100 мільярдів операцій на секунду. Крім того, за відсутності солі (Unsalted Hashing) однакові паролі завжди дають однаковий геш, що дозволяє створювати попередньо обчислені таблиці зворотного пошуку (Rainbow Tables). Наприклад, геш MD5 від типового пароля Passw0rd! (c73294c653457a80b852dbb09ef0a4d6) відновлюється в базах на кшталт CrackStation миттєво.


![Рисунок 2.12 — Експериментальне порівняння стійкості гешування (MD5 vs SHA-1 vs Salted PBKDF2) у Swagger UI](./screenshots/12_swagger_rainbow_table_demo.png)
*Рисунок 2.12 — Експериментальне порівняння стійкості гешування (MD5 vs SHA-1 vs Salted PBKDF2) у Swagger UI*

Архітектурний захист: Для надійного захисту паролів у сучасних .NET бекендах стандартом є застосування функцій формування ключа на основі пароля з параметром складності (Key Derivation Functions): PBKDF2, Argon2id або BCrypt. Кожен користувач отримує індивідуальну 128-бітну випадкову сіль, згенеровану криптографічно надійним генератором RandomNumberGenerator. Кількість ітерацій (100 000) штучно уповільнює перебір на GPU, роблячи офлайн-атаки економічно неможливими.


## 4. Зведена матриця результатів верифікації безпеки (OWASP A2)

Результати експериментальної верифікації: У таблиці 1 наведено порівняльний аналіз реалізованих механізмів автентифікації у проєкті TechFix Enterprise, досліджені вразливості та результати верифікації після впровадження захисту.


| Аспект безпеки | CWE / Стандарт | Тестовий вектор | Вразлива поведінка | Результат після Remediation |
| --- | --- | --- | --- | --- |
| Збереження паролів | CWE-522, CWE-798 | devadmin / techfix2026! | Вхід через захардкоджений бекдор, паролі відкритим текстом | PBKDF2-SHA256 (100k ітерацій) з 128-біт сіллю, бекдор ліквідовано. |
| Управління виходом | CWE-613, CWE-384 | Replay SESS-7b2f після логауту | Сесія залишається валідною на сервері необмежено довго | Токен додано до Revocation Blacklist, повторний доступ заблоковано. |
| Атаки перебором | CWE-307, CWE-204 | Автоматизований перебір словником | User Enumeration (витік існування логіна), необмежені спроби | Account Lockout після 3 спроб (HTTP 429), уніфіковані помилки. |
| Адмін-портали | CWE-565, CWE-287 | Cookie: admin=1 | Повний витік фінансів та майстер-ключа шифрування | 401/403: Обов'язкова валідація підписаного JWT токена. |
| JWT токени | CVE-2015-9235 | {"alg":"none"} + role: Admin | Прийняття фальсифікованого токена без перевірки підпису | Security Policy Violation: відхилення токенів без підпису HMAC-SHA256. |
| Райдужні таблиці | CWE-328, CWE-916 | Passw0rd! у базі CrackStation | Миттєвий злам Unsalted MD5/SHA-1 (<0.001 сек) | Salted PBKDF2: кожна сіль вимагає нової таблиці, атака неможлива. |



## 5. Відповіді на контрольні запитання

1. Яка роль випадкової солі (Salt) та чому вона унеможливлює використання райдужних таблиць?
Криптографічна сіль (Salt) — це криптографічно надійна випадкова послідовність байтів, яка генерується індивідуально для кожного користувача і додається до пароля перед гешуванням. Навіть якщо два користувачі мають абсолютно однаковий пароль, їхні підсумкові геші будуть принципово різними. Це повністю нівелює можливість застосування попередньо обчислених словників та райдужних таблиць (Rainbow Tables), оскільки для кожної унікальної солі зловмиснику довелося б заново розраховувати всю багатотерабайтну таблицю.

2. У чому полягає суть вразливості JWT alg: none (CVE-2015-9235) та як їй запобігти?
Уразливість виникає, коли система безпеки не перевіряє алгоритм цифрового підпису на стороні сервера, а сліпо бере його з JSON-заголовка токена, надісланого клієнтом. Відповідно до стандарту RFC 7519, алгоритм 'none' позначає токени без підпису. Зловмисник може змінити у корисному навантаженні токена роль з 'User' на 'Admin', видалити підпис та вказати 'alg': 'none'. Вразливий бек-енд вважає такий токен валідним і надає зловмиснику найвищі адміністративні привілеї. Для захисту сервер повинен жорстко ігнорувати заголовок 'alg' і вимагати виключно узгоджений алгоритм (наприклад, HS256 або RS256).

3. Які технічні заходи є необхідними для надійного захисту системи від атак повним перебором (Brute Force)?
Для запобігання перебору застосовується комплексний підхід: 1) Rate Limiting на рівні IP-адреси та облікового запису (лімітування частоти запитів через Sliding Window); 2) Політика блокування облікового запису (Account Lockout Policy) після 3-5 поспіль невдалих спроб на фіксований час (5-15 хвилин); 3) Уніфікація відповідей про помилки (Generic Error Messages), що не дає змоги зловмиснику визначити, яка саме частина облікових даних є хибною; 4) Впровадження штучної затримки (Constant-Time Delay) для захисту від аналізу часу відповіді (Timing Attacks); 5) Використання багатофакторної автентифікації (MFA).

4. Як принципи Clean Architecture допомагають створити надійний захист підсистеми автентифікації?
Чиста архітектура ізолює бізнес-правила від деталей передачі автентифікаційних даних через мережу. Сутність користувача у шарі Domain взагалі не містить паролів у відкритому вигляді. Рівень Application оперує інтерфейсами (IAuthenticationService) та строго валідованими DTO. Рівень Infrastructure інкапсулює стійку криптографію, а рівень WebApi виступає захисним шлюзом з middleware-перевірками JWT Claims, RateLimiter та політиками авторизації [Authorize]. Така багатоешелонна структура забезпечує принцип Defense in Depth.


## 6. Висновки

Підсумки роботи: У ході виконання лабораторної роботи №2 було ґрунтовно досліджено категорію загроз OWASP Top 10 A2: Broken Authentication на базі створеного корпоративного серверного застосунку TechFix Enterprise на платформі .NET 10. Було реалізовано та експериментально протестовано 6 ключових напрямків компрометації автентифікації: використання захардкоджених бекдорів та відкритого зберігання паролів (CWE-798, CWE-522), відсутність серверного відкликання сесій (Session Replay / CWE-613), атаки перебором та витік існування користувача (CWE-307, CWE-204), підміна привілеїв через непідписані Cookie (CWE-565), фальсифікація JWT токенів через alg: none (CVE-2015-9235) та розкриття паролів через слабкі геші (CWE-328).

Практичне значення: Для кожної виявленої проблеми було розроблено та верифіковано надійне Secure Code Remediation рішення: впроваджено функцію формування ключів PBKDF2-SHA256 (100 000 ітерацій, 128-бітна сіль), розроблено механізм серверної інвалідації токенів Revocation Blacklist, налаштовано політику автоматичного блокування акаунта Account Lockout, реалізовано строгу перевірку підпису JWT HMAC-SHA256 з білим списком алгоритмів. Всі експерименти проведено в реальному Swagger UI на базі СУБД SQLite з фіксацією результатів.

Академічна відповідність: Проєкт збережено у версійному контролі Git (коміт 1861fdf) як логічне доповнення до Лабораторної роботи №1 без порушення її функціональності. Всі поставлені завдання виконано в повному обсязі відповідно до навчальних вимог ТНТУ.
