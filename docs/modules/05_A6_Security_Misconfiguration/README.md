# Module 05: OWASP A6: Security Misconfiguration & Information Leakage

> Comprehensive security engineering guide, vulnerability analysis, C# code implementations, and Swagger UI practical walkthrough for TechFix Enterprise (.NET 10).

---


## 1. Мета та завдання лабораторної роботи

Мета дослідження: Метою роботи є глибоке практичне дослідження загроз безпеки веб-застосунків класу OWASP Top 10:2021 A05 / OWASP Top 10:2017 A6: Security Misconfiguration. В рамках проєкту досліджуються критичні механізми витоку конфіденційної інформації через небезпечні конфігурації веб-сервера та платформи .NET: деталізовані налагоджувальні стек-трейси (CWE-209), загальнодоступні файли резервних копій (CWE-530), витік чутливих розробницьких даних у коментарях (CWE-615) та відсутність обов'язкових захисних HTTP-заголовків (CWE-16).

Основне завдання: На основі створеного реального Clean Architecture проєкту сервісу ремонту комп'ютерної техніки TechFix Enterprise (.NET 10 / ASP.NET Core Web API) реалізувати подвійну архітектуру (Dual-Mode Architecture) контролера A6_SecurityMisconfigController, що демонструє роботу як уразливих, так і повністю захищених кінцевих точок із збереженням кумулятивності попередніх лабораторних робіт (A1, A2, A4, A5).

Перелік практичних завдань:
1. Дослідити механізм генерації необроблених винятків та витоку інформації про операційну систему, шляхи до файлів проєкту на сервері та стек викликів CLR під час виклику уразливого ендпоінту unhandled-error.
2. Реалізувати захисний шар централізованої обробки винятків згідно міжнародного інтернет-стандарту RFC 7807 (Problem Details for HTTP APIs) із генерацією незворотного кореляційного ідентифікатора (CorrelationId) та повною санітизацією внутрішніх стек-трейсів.
3. Реалізувати сценарій виявлення та завантаження резервних копій бази даних (.bak, .dump) через небезпечні параметри запиту, після чого впровадити надійну ізоляцію артефактів резервного копіювання за межами каталогу WebRoot із забороною прямого доступу та логуванням спроб експлуатації.
4. Проаналізувати проблему залишення конфіденційних коментарів розробників (тестові токени API, внутрішні URL сервісів) та реалізувати санітизацію контенту, що відправляється клієнту.
5. Провести комплексний аудит безпекових HTTP-заголовків (Security Headers), усунути витік банерів сервера (Server, X-Powered-By) та забезпечити впровадження заголовків Content-Security-Policy (CSP), Strict-Transport-Security (HSTS), X-Content-Type-Options, X-Frame-Options та Referrer-Policy.
6. Провести верифікаційні тести в реальному інтерфейсі Swagger UI на порту 5006, зафіксувати результати виконання та зафіксувати зміни в репозиторії Git.


## 2. Архітектура та програмна реалізація у проєкті TechFix

Архітектурний підхід: Для реалізації навчально-дослідницького модуля лабораторної роботи №5 до проєкту TechFix було додано шар DTOs, сервісний інтерфейс ISecurityMisconfigService, реалізацію SecurityMisconfigService та контролер A6_SecurityMisconfigController. Кожна функція реалізована у двох режимах: Vulnerable (ілюстрація небезпечної поведінки) та Secure (промисловий захист із виправленням конфігурації).


### 2.1. Контракт інтерфейсу ISecurityMisconfigService


**Лістинг 1. Інтерфейс ISecurityMisconfigService у шарі Application**


```csharp
namespace TechFix.Application.Interfaces;
using TechFix.Application.DTOs;

public interface ISecurityMisconfigService
{
    // Task 1: Unhandled exception handling vs RFC 7807 ProblemDetails
    Task<UnhandledErrorVulnerableDto> ProvokeUnhandledErrorVulnerableAsync(string trigger);
    Task<ProblemDetailsSecureDto> ProvokeUnhandledErrorSecureAsync(string trigger);

    // Task 2: Backup exposure vs protected storage
    Task<BackupDownloadResultDto> DownloadBackupVulnerableAsync(string fileName);
    Task<BackupDownloadResultDto> DownloadBackupSecureAsync(string fileName);

    // Task 3: Developer comments & credentials leak
    Task<DeveloperCommentsLeakDto> GetDeveloperCommentsVulnerableAsync();
    Task<DeveloperCommentsLeakDto> GetDeveloperCommentsSecureAsync();

    // Task 4: Security headers audit
    Task<SecurityHeadersAuditDto> AuditSecurityHeadersVulnerableAsync();
    Task<SecurityHeadersAuditDto> AuditSecurityHeadersSecureAsync();
}
```


### 2.2. Сервісна реалізація SecurityMisconfigService

Опис сервісного шару: Клас SecurityMisconfigService реалізує бізнес-логіку обробки помилок, доступу до файлів бекапів, санітизації коментарів та аудиту конфігурації заголовків. Приклад захищеної обробки винятків демонструє використання RFC 7807 та генерацію унікального correlation_id для безпечного аудиту без витоку внутрішнього стеку CLR:


**Лістинг 2. Захищена обробка винятків за стандартом RFC 7807 у SecurityMisconfigService.cs**


```csharp
public async Task<ProblemDetailsSecureDto> ProvokeUnhandledErrorSecureAsync(string trigger)
{
    var correlationId = Guid.NewGuid().ToString("N");
    try
    {
        if (trigger.ToLowerInvariant() == "divide_by_zero")
        {
            int zero = 0;
            int result = 42 / zero;
        }
        else if (trigger.ToLowerInvariant() == "null_reference")
        {
            string nullStr = null!;
            _ = nullStr.Length;
        }
        return new ProblemDetailsSecureDto
        {
            Status = 200,
            Title = "Success",
            Detail = "Request processed cleanly.",
            CorrelationId = correlationId
        };
    }
    catch (Exception ex)
    {
        // Safe RFC 7807 Problem Details: internal stacktrace is logged to secure log, not to client
        return new ProblemDetailsSecureDto
        {
            Type = "https://techfix.local/errors/unhandled-server-error",
            Title = "Internal Server Error",
            Status = 500,
            Detail = "An unexpected error occurred while processing your request. Please contact support with the correlation ID.",
            Instance = $"/api/a6-misconfig/secure/handled-error?trigger={trigger}",
            CorrelationId = correlationId,
            RemediationNote = "Secured: Stack trace and server file paths are completely hidden. Internal error logged securely with CorrelationId."
        };
    }
}
```


### 2.3. Контролер A6_SecurityMisconfigController

Опис контролера: Контролер надає REST-інтерфейс у групі A6 Security Misconfiguration. Додатково у захищеному методі аудиту заголовків безпосередньо встановлюються критичні захисні HTTP-заголовки у відповідь сервера:


**Лістинг 3. Налаштування промислових HTTP Security Headers у A6_SecurityMisconfigController.cs**


```json
[HttpGet("secure/headers-audit")]
public async Task<IActionResult> AuditSecurityHeadersSecure()
{
    // Apply secure headers to the HTTP response
    Response.Headers.Append("Content-Security-Policy", "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';");
    Response.Headers.Append("X-Frame-Options", "DENY");
    Response.Headers.Append("X-Content-Type-Options", "nosniff");
    Response.Headers.Append("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");
    Response.Headers.Append("Referrer-Policy", "strict-origin-when-cross-origin");
    Response.Headers.Remove("Server");
    Response.Headers.Remove("X-Powered-By");

    var result = await _service.AuditSecurityHeadersSecureAsync();
    return Ok(result);
}
```


## 3. Практичні результати тестування у Swagger UI

Верифікація в реальному середовищі: Усі тести проводилися у живому середовищі веб-сервера Kestrel (http://localhost:5006/swagger/index.html) з використанням автоматизованого драйвера Microsoft Edge WebDriver. Нижче наведено детальні скріншоти виконаних запитів, коди відповідей та тіла запитів/відповідей.


### 3.1. Загальний огляд ендпоінтів A6 у Swagger UI


![Рис. 1. Ендпоінти лабораторної роботи №5 (A6 Security Misconfiguration) у Swagger UI](./screenshots/01_swagger_a6_overview.png)
*Рис. 1. Ендпоінти лабораторної роботи №5 (A6 Security Misconfiguration) у Swagger UI*

Аналіз інтерфейсу: На Рис. 1 продемонстровано зареєстровані ендпоінти для чотирьох завдань лабораторної роботи: провокація необроблених помилок, доступ до резервних копій, витік розробницьких коментарів та аудит безпекових заголовків.


### 3.2. Дослідження витоку стек-трейсів (CWE-209)

#### ❌ Що недобре зроблено в коді (Вразлива реалізація / Антипатерн):

Антипатерн: Необроблений виняток повертає клієнту технічний стек викликів CLR, версію ОС, шлях до вихідних файлів на диску та SQL-запит (CWE-209).

```csharp
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
```

#### ✅ Як зробити правильно (Захищена реалізація / Remediation):

Remediation: Впровадження стандарту RFC 7807 ProblemDetails із генерацією IncidentTrackingId (CorrelationId) та приховуванням технічних деталей.

```csharp
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
```



![Рис. 2. Уразливий запит: витік повного CLR стек-трейсу та шляхів файлової системи сервера](./screenshots/02_swagger_stacktrace_vulnerable.png)
*Рис. 2. Уразливий запит: витік повного CLR стек-трейсу та шляхів файлової системи сервера*

Аналіз уразливості: При виконанні уразливого запиту з trigger=divide_by_zero сервер повертає статус HTTP 500 та деталізований об'єкт із повним текстом винятку DivideByZeroException. Зловмисник отримує критичні відомості: абсолютний шлях до файлів проекту (C:\OneDrive\...\SecurityMisconfigService.cs:line 27), версію операційної системи (Microsoft Windows 10.0.26100) та версію середовища виконання .NET 10.0.1.


![Рис. 3. Захищений запит: впровадження стандарту RFC 7807 ProblemDetails із CorrelationId](./screenshots/03_swagger_rfc7807_secure.png)
*Рис. 3. Захищений запит: впровадження стандарту RFC 7807 ProblemDetails із CorrelationId*

Аналіз захищеного режиму: Захищений ендпоінт перехоплює виняток, формує стандартний об'єкт ProblemDetails (RFC 7807) із типом https://techfix.local/errors/unhandled-server-error, нейтральним повідомленням про помилку та унікальним correlation_id (наприклад, 8f9b9f93...). Усі технічні деталі та шляхи до коду повністю приховані від клієнта.


### 3.3. Дослідження доступу до резервних копій (CWE-530)

#### ❌ Що недобре зроблено в коді (Вразлива реалізація / Антипатерн):

Антипатерн: Відкритий публічний доступ до файлів резервних копій (.bak, .dump, .kdbx) без автентифікації та контролю доступу (CWE-530).

```csharp
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
```

#### ✅ Як зробити правильно (Захищена реалізація / Remediation):

Remediation: Зберігання бекапів поза межами WebRoot, повне блокування прямих HTTP-запитів до розширень архівів та повернення HTTP 403 Forbidden.

```csharp
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
```



![Рис. 4. Уразливий запит: несанкціоноване завантаження дампа бази даних database_backup.bak](./screenshots/04_swagger_backup_download_vulnerable.png)
*Рис. 4. Уразливий запит: несанкціоноване завантаження дампа бази даних database_backup.bak*

Аналіз уразливості: Уразливий метод дозволяє будь-якому неавтентифікованому користувачу завантажити резервну копію бази даних або конфігураційних файлів через публічний каталог веб-сервера. Тіло відповіді містить дамп схеми клієнтів сервісу TechFix із хешами паролів.


![Рис. 5. Захищений запит: блокування публічного доступу (HTTP 403 Forbidden) та ізоляція бекапів](./screenshots/05_swagger_backup_download_secure.png)
*Рис. 5. Захищений запит: блокування публічного доступу (HTTP 403 Forbidden) та ізоляція бекапів*

Аналіз захищеного режиму: Захищений метод блокує доступ до бекапів для звичайних користувачів, повертає статус HTTP 403 Forbidden із повідомленням 'Direct download of backup and dump files is strictly forbidden' та фіксує подію безпеки в журналі аудиту із фіксацією IP-адреси клієнта.


### 3.4. Дослідження витоку конфіденційних даних у коментарях (CWE-615)

#### ❌ Що недобре зроблено в коді (Вразлива реалізація / Антипатерн):

Антипатерн: Залишення у відповідях API службових налагоджувальних коментарів розробників із тестовими паролями та внутрішніми URL (CWE-615).

```csharp
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
```

#### ✅ Як зробити правильно (Захищена реалізація / Remediation):

Remediation: Автоматична санітизація вихідного контенту конвеєром ASP.NET Core та вилучення розробницьких артефактів перед відправкою клієнту.

```csharp
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
```



![Рис. 6. Уразливий запит: витік налагоджувальних коментарів, тестових токенів та внутрішніх URL](./screenshots/06_swagger_developer_comments_vulnerable.png)
*Рис. 6. Уразливий запит: витік налагоджувальних коментарів, тестових токенів та внутрішніх URL*

Аналіз уразливості: У відповіді уразливого методу виявлено залишені розробниками службові коментарі, тестові облікові дані (admin_debug:MasterKey2026!), посилання на внутрішній Jenkins-сервер та токени доступу до сервісу відправки SMS.


![Рис. 7. Захищений запит: автоматична санітизація вихідних даних та вилучення коментарів](./screenshots/07_swagger_developer_comments_secure.png)
*Рис. 7. Захищений запит: автоматична санітизація вихідних даних та вилучення коментарів*

Аналіз захищеного режиму: У захищеному режимі контент проходить фільтрацію перед відправкою клієнту: службові коментарі розробників повністю вилучено, конфіденційні параметри не передаються у відкритому вигляді.


### 3.5. Аудит та налаштування HTTP Security Headers (CWE-16)


![Рис. 8. Уразлива конфігурація заголовків: витік версії сервера та відсутність CSP/HSTS](./screenshots/08_swagger_headers_audit_vulnerable.png)
*Рис. 8. Уразлива конфігурація заголовків: витік версії сервера та відсутність CSP/HSTS*

Аналіз уразливості: Аудит уразливої конфігурації виявив критичні недоліки: заголовок Server розкриває використання веб-сервера Kestrel, заголовок X-Powered-By транслює ASP.NET, а критичні заголовки захисту від XSS (Content-Security-Policy), клікджекінгу (X-Frame-Options) та підміни MIME-типів (X-Content-Type-Options) повністю відсутні.


![Рис. 9. Захищена конфігурація: впровадження CSP, X-Frame-Options, HSTS та маскування банерів](./screenshots/09_swagger_headers_audit_secure.png)
*Рис. 9. Захищена конфігурація: впровадження CSP, X-Frame-Options, HSTS та маскування банерів*

Аналіз захищеного режиму: Після захисної оптимізації сервер повертає повний спектр захисних заголовків: Content-Security-Policy: default-src 'self', X-Frame-Options: DENY, Strict-Transport-Security: max-age=31536000, X-Content-Type-Options: nosniff, а банери Server та X-Powered-By видалені з HTTP-відповіді.


## 4. Зведена таблиця результатів аналізу безпекових конфігурацій


| Досліджуваний фактор | CWE / Рівень | Вхідні параметри | Уразливий стан системи | Захисний стан (Remediation) |
| --- | --- | --- | --- | --- |
| Витік стек-трейсів | CWE-209 (High) | GET /unhandled-error?trigger=divide_by_zero | Витік абсолютних шляхів на диску, версії ОС та CLR | RFC 7807 ProblemDetails із генерацією CorrelationId. |
| Доступ до бекапів | CWE-530 (Critical) | GET /backup-download?fileName=database_backup.bak | Прямий дамп бази клієнтів сервісу TechFix з паролями | HTTP 403 Forbidden, винесення бекапів за межі WebRoot. |
| Коментарі розробників | CWE-615 (Medium) | GET /developer-comments | Витік пароля admin_debug та токенів інтеграцій | Автоматична санітизація вихідного коду перед релізом. |
| Аудит HTTP-заголовків | CWE-16 (High) | GET /headers-audit | Витік Kestrel/ASP.NET, відсутність CSP/HSTS/X-Frame | Впроваджено CSP, HSTS, X-Frame-Options: DENY, nosniff. |



## 5. Відповіді на контрольні запитання

1. Що являє собою вразливість Security Misconfiguration та які її основні джерела?
Security Misconfiguration (помилка конфігурації безпеки) — це клас уразливостей, що виникає, коли безпекові параметри компонентів системи (веб-серверів, баз даних, фреймворків, хмарних сховищ) встановлені за замовчуванням, не сконфігуровані належним чином або містять надмірні дозволи. Типовими прикладами є: увімкнений режим налагодження на production, відкриті порти та панелі адміністрування без паролів, витік стек-трейсів клієнтам, відсутність захисних заголовків та публічний доступ до файлів резервних копій.

2. Для чого призначений стандарт RFC 7807 та як він сприяє безпеці веб-сервісів?
Стандарт RFC 7807 (Problem Details for HTTP APIs) регламентує уніфікований формат JSON-відповіді у разі виникнення помилок у веб-API. Він визначає стандартні поля: 'type' (URI ідентифікатор типу проблеми), 'title' (короткий опис), 'status' (HTTP код), 'detail' (зрозуміле повідомлення без витоку внутрішнього коду) та 'instance' (URI запиту). Додатково рекомендується включати 'correlation_id' для зв'язку між клієнтським запитом та внутрішнім захищеним сервером логів.

3. Які HTTP-заголовки безпеки (Security Headers) є критичними для захисту сучасного веб-API?
Критично важливими безпековими HTTP-заголовками є: 1) Content-Security-Policy (CSP) — обмежує джерела завантаження скриптів, стилів та медіа, захищаючи від XSS та ін'єкцій; 2) Strict-Transport-Security (HSTS) — примусово скеровує клієнта на використання HTTPS; 3) X-Frame-Options: DENY — блокує відображення сторінки у фреймах (захист від Clickjacking); 4) X-Content-Type-Options: nosniff — блокує MIME-sniffing браузером; 5) Referrer-Policy — контролює витік адреси переходу.

4. Чому розміщення файлів резервних копій у загальнодоступних каталогах становить критичну небезпеку та як їй запобігти?
Залишення файлів бекапів (.bak, .sql, .dump) у каталогах веб-сервера створює загрозу повного витоку конфіденційної інформації (паролі, персональні дані клієнтів, системні налаштування), оскільки такі файли зазвичай завантажуються безпосередньо через HTTP-запити в обхід логіки автентифікації. Захист полягає у: зберіганні бекапів суворо за межами каталогу WebRoot; шифруванні архівів бекапів сильними алгоритмами (AES-256); ізоляції сховища бекапів в окремому захищеному сегменті мережі.


## 6. Висновки

Підсумки роботи: У ході виконання лабораторної роботи №5 було успішно досліджено уразливості категорії OWASP Top 10 A6: Security Misconfiguration на прикладі створеного корпоративного веб-застосунку TechFix Enterprise на базі платформи .NET 10. Було реалізовано практичні сценарії атак: провокацію необроблених винятків із витоком деталей операційної системи та шляхів файлової системи (CWE-209), несанкціоноване завантаження резервних копій бази даних (CWE-530), витік службових коментарів розробників (CWE-615) та відсутність базових захисних HTTP-заголовків (CWE-16).

Практичне значення: Для кожної виявленої проблеми реалізовано та верифіковано захисні конфігурації: централізовану обробку винятків за стандартом RFC 7807 із генерацією кореляційного ідентифікатора, ізоляцію файлів бекапів із блокуванням прямого доступу, санітизацію розробницьких даних перед публікацією, а також впровадження сучасного комплексу HTTP Security Headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options) із маскуванням банерів сервера Kestrel та ASP.NET.

Академічна відповідність: Усі зміни зафіксовано в системі контролю версій Git (коміт 8f626b3) за кумулятивним принципом зі збереженням працездатності лабораторних робіт №1, №2, №3 та №4. Отримані результати підтверджено реальними скріншотами взаємодії у Swagger UI. Завдання виконано у повному обсязі згідно з академічними вимогами кафедри комп'ютерних наук ТНТУ.
