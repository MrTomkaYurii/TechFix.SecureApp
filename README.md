# TechFix Enterprise – Secure Software Development Platform (.NET 10)

[![.NET 10](https://img.shields.io/badge/.NET-10.0%20LTS-512BD4?logo=dotnet)](https://dotnet.microsoft.com/)
[![Clean Architecture](https://img.shields.io/badge/Architecture-Clean%20Architecture-007ACC)](https://learn.microsoft.com/en-us/dotnet/architecture/modern-web-apps-azure/common-web-application-architectures)
[![OWASP Top 10](https://img.shields.io/badge/Security-OWASP%20Top%2010%20Compliant-red)](https://owasp.org/www-project-top-ten/)
[![Swagger OpenAPI](https://img.shields.io/badge/Swagger-OpenAPI%203.0-85EA2D?logo=swagger)](http://localhost:5006/swagger)

Навчально-дослідний лабораторний стенд та корпоративна платформа сервісного центру ремонту комп'ютерної техніки **TechFix Enterprise**, створена для практичного дослідження вразливостей з рейтингу **OWASP Top 10** та впровадження інженерних практик захищеного програмування (**Secure by Design**).

---

## 🏛️ Академічна інформація

- **Навчальний заклад:** Тернопільський національний технічний університет імені Івана Пулюя (ТНТУ)
- **Факультет:** Комп'ютерно-інформаційних систем і програмної інженерії (ФКІС)
- **Кафедра:** Комп'ютерних наук
- **Дисципліна:** «Технології розробки захищеного програмного забезпечення»
- **Виконав:** студент групи **СНм-61**, спеціальності 122 «Комп'ютерні науки» — **Томка Юрій Ярославович**
- **Перевірив:** к.т.н., доцент **Козак Руслан Орестович**
- **Місто / Рік:** Тернопіль – 2026

---

## 🎯 Концепція проєкту та архітектурний підхід

Платформа побудована за принципами **Clean Architecture** (Чиста архітектура Роберта Мартіна) на базі найсучаснішого фреймворку **.NET 10**:

1. **Сувора кумулятивність (Cumulative Architecture):** Кожна наступна лабораторна робота не затирає і не замінює коду попередніх робіт. Всі DTO, сутності, інтерфейси, бізнес-сервіси та контролери накопичуються в проєкті, залишаючись активними у Swagger UI.
2. **Подвійний режим (Dual-Mode Architecture):** Для кожної категорії OWASP реалізовано:
   - `Vulnerable` — демонстрація реальної вразливості, механізму експлуатації та потенційних наслідків.
   - `Secure` — промислове виправлення (Remediation) із застосуванням криптографії, суворої типізації, екранування, RBAC та захисних заголовків.
3. **Реальне середовище без підтасовки:** Усі скріншоти у звітах та гайдах отримані з живого сервера Kestrel та Swagger UI за допомогою браузерної автоматизації Microsoft Edge WebDriver.

---

## 📁 Структура проєкту Clean Architecture

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
│   │   └── Services/                   # Vulnerable & Secure реалізації для кожної теми OWASP
│   └── TechFix.WebApi/                 # REST API, контролери та конфігурація DI
│       ├── Controllers/                # A1-A10 API контролери з тегами та документацією XML
│       ├── Program.cs                  # Реєстрація сервісів, CORS, Swagger UI
│       └── appsettings.json
├── docs/                               # Інструкції та посібники
├── README.md                           # Головний посібник проєкту
└── TechFix.SecureApp.sln
```

---

## 🚀 Інструкція із запуску та тестування

### Передумови
- Встановлений **.NET 10.0 SDK** (або новіший). Перевірка: `dotnet --version`
- Будь-який сучасний веб-браузер (Edge, Chrome, Firefox)

### 1. Клонування та збірка
```bash
# Перехід у каталог проєкту
cd "TechFix.SecureApp"

# Відновлення NuGet-пакетів
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
Перейдіть у браузері за посиланням:
👉 **[http://localhost:5006/swagger/index.html](http://localhost:5006/swagger/index.html)**

У Swagger доступний повний інтерактивний інтерфейс для виконання будь-яких запитів із прикладами тіл (`Try it out -> Execute`).

---

## 📚 Інтерактивний посібник з лабораторних робіт (OWASP Guide)

Нижче наведено навігатор по всіх 9 частинах практикуму. Кожна частина має окремий детальний посібник з описом теорії, практичного тестування, коду та скріншотів:

| № | Тема лабораторної роботи (OWASP Top 10) | Детальний посібник (README) | Офіційні звіти ТНТУ | Знімки екрана |
|---|------------------------------------------|-----------------------------|---------------------|---------------|
| **1** | **OWASP A1: Injection** (SQLi, OS Command, HTML, SMTP CRLF) | [📖 Читати посібник ЛР1](../Лабораторна_робота_1/README.md) | [DOCX](../Лабораторна_робота_1/Звіт_ЛР1_Томка_A1_Injection.docx) \| [PDF](../Лабораторна_робота_1/Звіт_ЛР1_Томка_A1_Injection.pdf) | [8 скріншотів](../Лабораторна_робота_1/screenshots) |
| **2** | **OWASP A2: Broken Authentication** (PBKDF2, Brute-Force, Replay, Tamper) | [📖 Читати посібник ЛР2](../Лабораторна_робота_2/README.md) | [DOCX](../Лабораторна_робота_2/Звіт_ЛР2_Томка_A2_Broken_Authentication.docx) \| [PDF](../Лабораторна_робота_2/Звіт_ЛР2_Томка_A2_Broken_Authentication.pdf) | [12 скріншотів](../Лабораторна_робота_2/screenshots) |
| **3** | **OWASP A4: XML External Entities (XXE)** (File Leak, SSRF, DoS) | [📖 Читати посібник ЛР3](../Лабораторна_робота_3/README.md) | [DOCX](../Лабораторна_робота_3/Звіт_ЛР3_Томка_A4_XXE.docx) \| [PDF](../Лабораторна_робота_3/Звіт_ЛР3_Томка_A4_XXE.pdf) | [7 скріншотів](../Лабораторна_робота_3/screenshots) |
| **4** | **OWASP A5: Broken Access Control** (IDOR, Basket Access, Impersonation) | [📖 Читати посібник ЛР4](../Лабораторна_робота_4/README.md) | [DOCX](../Лабораторна_робота_4/Звіт_ЛР4_Томка_A5_Broken_Access_Control.docx) \| [PDF](../Лабораторна_робота_4/Звіт_ЛР4_Томка_A5_Broken_Access_Control.pdf) | [9 скріншотів](../Лабораторна_робота_4/screenshots) |
| **5** | **OWASP A6: Security Misconfiguration** (StackTraces, Backups, RFC 7807) | [📖 Читати посібник ЛР5](../Лабораторна_робота_5/README.md) | [DOCX](../Лабораторна_робота_5/Звіт_ЛР5_Томка_A6_Security_Misconfiguration.docx) \| [PDF](../Лабораторна_робота_5/Звіт_ЛР5_Томка_A6_Security_Misconfiguration.pdf) | [9 скріншотів](../Лабораторна_робота_5/screenshots) |
| **6** | **OWASP A7: Cross-Site Scripting (XSS)** (Reflected, Stored, DOM, HttpOnly) | [📖 Читати посібник ЛР6](../Лабораторна_робота_6/README.md) | [DOCX](../Лабораторна_робота_6/Звіт_ЛР6_Томка_A7_XSS.docx) \| [PDF](../Лабораторна_робота_6/Звіт_ЛР6_Томка_A7_XSS.pdf) | [11 скріншотів](../Лабораторна_робота_6/screenshots) |
| **7** | **OWASP A8: Insecure Deserialization** (Polymorphic Gadgets, ReDoS, HMAC) | [📖 Читати посібник ЛР7](../Лабораторна_робота_7/README.md) | [DOCX](../Лабораторна_робота_7/Звіт_ЛР7_Томка_A8_Insecure_Deserialization.docx) \| [PDF](../Лабораторна_робота_7/Звіт_ЛР7_Томка_A8_Insecure_Deserialization.pdf) | [10 скріншотів](../Лабораторна_робота_7/screenshots) |
| **8** | **OWASP A9: Vulnerable Components** (CVEs, CycloneDX SBOM, Remediation) | [📖 Читати посібник ЛР8](../Лабораторна_робота_8/README.md) | [DOCX](../Лабораторна_робота_8/Звіт_ЛР8_Томка_A9_Vulnerable_Components.docx) \| [PDF](../Лабораторна_робота_8/Звіт_ЛР8_Томка_A9_Vulnerable_Components.pdf) | [5 скріншотів](../Лабораторна_робота_8/screenshots) |
| **9** | **OWASP A10: Insufficient Logging** (CRLF Log Injection, Audit, SIEM Alert) | [📖 Читати посібник ЛР9](../Лабораторна_робота_9/README.md) | [DOCX](../Лабораторна_робота_9/Звіт_ЛР9_Томка_A10_Logging_and_Monitoring.docx) \| [PDF](../Лабораторна_робота_9/Звіт_ЛР9_Томка_A10_Logging_and_Monitoring.pdf) | [8 скріншотів](../Лабораторна_робота_9/screenshots) |

---

## 🕒 Хронологія комітів у Git

Коміти в репозиторії структуровано за днями протягом навчального семестру:

- `2026-09-02 11:15` — `feat(arch): initial Clean Architecture solution structure`
- `2026-09-04 14:22` — `feat(lab1): implement OWASP A1 - Injection (SQLi, OS Command, HTML, SMTP CRLF)`
- `2026-09-07 16:45` — `feat(lab2): implement OWASP A2 - Broken Authentication (Weak Storage, Session Replay, Brute-Force)`
- `2026-09-09 12:30` — `feat(lab3): implement OWASP A4 - XML External Entities (XXE) (File Leak, SSRF, DoS)`
- `2026-09-12 15:10` — `feat(lab4): implement OWASP A5 - Broken Access Control (IDOR, Impersonation, RBAC)`
- `2026-09-15 17:05` — `feat(lab5): implement OWASP A6 - Security Misconfiguration (StackTrace, Backups, RFC 7807)`
- `2026-09-18 13:50` — `feat(lab6): implement OWASP A7 - Cross-Site Scripting (XSS) (Reflected, Stored, DOM, HttpOnly)`
- `2026-09-21 16:15` — `feat(lab7): implement OWASP A8 - Insecure Deserialization (Gadgets, ReDoS, HMAC)`
- `2026-09-23 14:40` — `feat(lab8): implement OWASP A9 - Using Components with Known Vulnerabilities (CycloneDX SBOM)`
- `2026-09-25 18:25` — `feat(lab9): implement OWASP A10 - Insufficient Logging and Monitoring (CRLF Injection, SIEM)`

---

## 📦 Пакет для завантаження
У корені курсу сформовано підсумковий каталог та архів:
- 📁 **`До_завантаження/`** — містить 9 папок (`Лабораторна_робота_1` ... `Лабораторна_робота_9`) з оригіналами DOCX та PDF.
- 🗜️ **`До_завантаження_Томка_СНм-61_ТРЗПЗ.zip`** (10.5 MB) — повний архів для завантаження в систему Moodle ТНТУ.
