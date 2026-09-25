# TechFix Enterprise – Secure Software Development Platform (.NET 10)

[![.NET 10](https://img.shields.io/badge/.NET-10.0%20LTS-512BD4?logo=dotnet)](https://dotnet.microsoft.com/)
[![Clean Architecture](https://img.shields.io/badge/Architecture-Clean%20Architecture-007ACC)](https://learn.microsoft.com/en-us/dotnet/architecture/modern-web-apps-azure/common-web-application-architectures)
[![OWASP Top 10](https://img.shields.io/badge/Security-OWASP%20Top%2010%20Compliant-red)](https://owasp.org/www-project-top-ten/)
[![Swagger OpenAPI](https://img.shields.io/badge/Swagger-OpenAPI%203.0-85EA2D?logo=swagger)](http://localhost:5006/swagger)

Навчально-дослідний стенд та корпоративна платформа сервісного центру ремонту комп'ютерної техніки **TechFix Enterprise**, створена для практичного дослідження вразливостей з рейтингу **OWASP Top 10** та впровадження інженерних практик захищеного програмування (**Secure by Design**).

---

## 🎯 Архітектурні принципи

Платформа спроєктована на базі **.NET 10** за принципами **Clean Architecture** (Чиста архітектура Роберта Мартіна) із дотриманням таких засад:

1. **Сувора кумулятивність (Cumulative Architecture):** Кожен модуль додає новий функціонал і контракти, не затираючи та не модифікуючи код попередніх частин. Всі DTO, сутності, інтерфейси, бізнес-сервіси та контролери залишаються активними в єдиному рішенні та доступні через Swagger UI.
2. **Подвійний режим (Dual-Mode Architecture):** Для кожної категорії OWASP реалізовано два паралельних шляхи виконання:
   - `Vulnerable` — демонстрація реальної вразливості, механізму експлуатації та потенційних загроз (PoC).
   - `Secure` — захищене промислове рішення (Remediation) із застосуванням криптографії, суворої типізації, екранування, RBAC та захисних заголовків.
3. **Реальне середовище виконання:** Усі тести та знімки екрана отримані з живого сервера Kestrel та інтерактивного Swagger UI.

---

## 📁 Структура проєкту

```text
TechFix.SecureApp/
├── src/
│   ├── TechFix.Domain/                 # Сутності бізнес-домену (Parts, Users, Orders, Baskets, Reviews)
│   │   ├── Entities/
│   │   └── Enums/
│   ├── TechFix.Application/            # Контракти інтерфейсів та моделі даних (DTOs)
│   │   ├── Interfaces/                 # IInjectionService, IAuthenticationService, IXxeService, etc.
│   │   └── DTOs/                       # Strongly-typed контракти запитів та відповідей
│   ├── TechFix.Infrastructure/         # Реалізація бізнес-логіки та доступ до даних
│   │   ├── Data/                       # TechFixDbContext (SQLite), початкове заповнення (Seeding)
│   │   └── Services/                   # Vulnerable & Secure сервіси для кожної теми OWASP
│   └── TechFix.WebApi/                 # REST API, контролери та конфігурація DI
│       ├── Controllers/                # API контролери з маршрутизацією та XML-документацією
│       ├── Program.cs                  # Реєстрація сервісів, CORS, Swagger UI
│       └── appsettings.json
├── docs/                               # Інженерні посібники та знімки Swagger UI
│   └── modules/                        # Модульні гайди для кожної вразливості OWASP
│       ├── 01_A1_Injection/
│       ├── 02_A2_Broken_Authentication/
│       ├── 03_A4_XXE/
│       ├── 04_A5_Broken_Access_Control/
│       ├── 05_A6_Security_Misconfiguration/
│       ├── 06_A7_XSS/
│       ├── 07_A8_Insecure_Deserialization/
│       ├── 08_A9_Vulnerable_Components/
│       └── 09_A10_Logging_and_Monitoring/
├── README.md                           # Головний посібник репозиторію
└── TechFix.slnx                        # Файл рішення
```

---

## 🚀 Інструкція із запуску та тестування

### Передумови
* Встановлений **.NET 10.0 SDK** (або новіший). Перевірка версії: `dotnet --version`
* Будь-який сучасний веб-браузер (Edge, Chrome, Firefox)

### 1. Клонування та збірка
```bash
# Перехід у робочий каталог
cd TechFix.SecureApp

# Відновлення залежностей NuGet
dotnet restore

# Компіляція рішення
dotnet build
```

### 2. Запуск бекенду
```bash
# Запуск веб-сервера Kestrel з HTTP-профілем
dotnet run --project src/TechFix.WebApi --launch-profile http
```
Сервер запуститься на адресі: **`http://localhost:5006/`**

### 3. Відкриття Swagger UI
Перейдіть у браузері за адресою:  
👉 **[http://localhost:5006/swagger/index.html](http://localhost:5006/swagger/index.html)**

У Swagger доступний повний інтерактивний інтерфейс для тестування будь-яких запитів із готовими прикладами тіл (`Try it out` -> `Execute`).

---

## 📚 Модулі безпеки та матриця вразливостей (OWASP Guide)

Нижче наведено зведену матрицю всіх реалізованих модулів із прямими посиланнями на детальні посібники, що містять опис теорії, лістинги коду та знімки екрана тестування:

| № | Категорія OWASP | Досліджувані вразливості (CWE) | Механізми захисту (Remediation) | Посібник з безпеки |
|:---:|---|---|---|:---:|
| **01** | **OWASP A1: Injection** | SQLi (CWE-89), OS Command Injection (CWE-78), HTMLi (CWE-79), SMTP CRLF (CWE-93) | Параметризація EF Core LINQ, мережевий API `Ping`, `HtmlEncoder`, валідація заголовків | [📖 Переглянути посібник](docs/modules/01_A1_Injection/README.md) |
| **02** | **OWASP A2: Broken Authentication** | Збереження у відкритому вигляді (CWE-522), Hardcoded Backdoor (CWE-798), Session Prediction, Brute-Force, JWT `alg:none` | PBKDF2 з криптографічною сіллю, крипто-рандом сесій, Lockout-політика, підпис HMAC-SHA256 | [📖 Переглянути посібник](docs/modules/02_A2_Broken_Authentication/README.md) |
| **03** | **OWASP A4: XML External Entities (XXE)** | Витік локальних файлів `SYSTEM` (CWE-611), Blind OOB SSRF (CWE-918), Billion Laughs DoS-бомба (CWE-776) | Відключення резолвінгу DTD (`XmlResolver = null`), заборона DTD, обмеження кількості символів ентіті | [📖 Переглянути посібник](docs/modules/03_A4_XXE/README.md) |
| **04** | **OWASP A5: Broken Access Control** | Горизонтальне підвищення прав / IDOR у замовленнях та кошиках (CWE-639), маніпуляція цінами, підміна ролей | Контекстна перевірка власника ресурсу, серверний розрахунок сум, рольова модель доступу (RBAC) | [📖 Переглянути посібник](docs/modules/04_A5_Broken_Access_Control/README.md) |
| **05** | **OWASP A6: Security Misconfiguration** | Витік StackTrace (CWE-209), публічні бекапи `.bak` та `.old` (CWE-530), витоки в коментарях (CWE-615), відсутність захисних заголовків | Стандартизовані помилки RFC 7807 ProblemDetails, вилучення налагоджувальних файлів, заголовки CSP, HSTS, X-Frame-Options | [📖 Переглянути посібник](docs/modules/05_A6_Security_Misconfiguration/README.md) |
| **06** | **OWASP A7: Cross-Site Scripting (XSS)** | Reflected XSS (CWE-79), Stored XSS у відгуках, DOM-based XSS, несанкціоноване читання `document.cookie` | Контекстне екранування виводу, санітизація, прапорці безпеки `HttpOnly; Secure; SameSite=Strict` | [📖 Переглянути посібник](docs/modules/06_A7_XSS/README.md) |
| **07** | **OWASP A8: Insecure Deserialization** | Поліморфні RCE-гаджети через `TypeNameHandling` (CWE-502), ReDoS катастрофічний бектрекінг (CWE-1333), фальсифікація стану сесії | Суворо типізовані DTO, відмова від небезпечних серіалізаторів, таймаути Regex, HMAC-SHA256 підпис стану | [📖 Переглянути посібник](docs/modules/07_A8_Insecure_Deserialization/README.md) |
| **08** | **OWASP A9: Vulnerable Components** | Відомі CVE у сторонніх бібліотеках (CWE-1395), застарілі транзитивні залежності | Формування CycloneDX SBOM, оновлення до безпечних .NET 10 LTS бібліотек, політики automated remediation | [📖 Переглянути посібник](docs/modules/08_A9_Vulnerable_Components/README.md) |
| **09** | **OWASP A10: Insufficient Logging & Monitoring** | Підміна записів журналу CRLF Log Injection (CWE-117), фінансові дії без аудиту (CWE-778), приховані атаки | Структуроване JSON-журналювання, незмінний хешований журнал аудиту, автоматичні порогові SIEM-алерти | [📖 Переглянути посібник](docs/modules/09_A10_Logging_and_Monitoring/README.md) |

---

## 🕒 Хронологія розробки (Commit History)

Історія репозиторію відображає послідовну реалізацію архітектури та модулів захисту:

```text
* f5b615f docs: add comprehensive project README, interactive security guide, and enable XML documentation for Swagger
* ec61f08 feat(lab9): implement OWASP A10 - Insufficient Logging and Monitoring with dual-mode audit endpoints
* dc70d46 feat(lab8): implement OWASP A9 - Using Components with Known Vulnerabilities with dual-mode audit endpoints
* 17fed66 feat(lab7): implement OWASP A8 - Insecure Deserialization with vulnerable and secure dual-mode endpoints
* e162ffb feat(lab6): implement OWASP A7 - Cross-Site Scripting (XSS) with vulnerable and secure dual-mode endpoints
* a4998e9 feat(lab5): implement OWASP A6 - Security Misconfiguration with vulnerable and secure endpoints
* 33c6a8b feat(lab4): implement OWASP A5 - Broken Access Control with vulnerable and secure endpoints
* 17d122b feat(lab3): implement OWASP A4 - XML External Entities (XXE) with vulnerable and secure endpoints
* 586d5aa feat(lab2): implement OWASP A2 - Broken Authentication with vulnerable and secure endpoints
* 257a236 feat(lab1): implement OWASP A1 - Injection with vulnerable and secure endpoints
* 7f80f12 feat(arch): initial Clean Architecture solution structure (Domain, Application, Infrastructure, WebApi)
```
