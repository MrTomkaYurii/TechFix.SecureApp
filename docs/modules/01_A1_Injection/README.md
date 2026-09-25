# Module 01: A1: Injection Flaws (SQLi, OS Command, HTML, SMTP)

> Practical security guide, attack vector demonstration in Swagger UI, and remediation architecture for TechFix Enterprise (.NET 10).

---

## 1. Теоретичні відомості

Уразливості класу **OWASP Top 10 A1: Injection (Ін'єкції)** виникають тоді, коли ненадійні користувацькі дані передаються безпосередньо інтерпретатору команд (SQL-рушій, командна оболонка ОС, поштовий сервер, HTML-парсер) у складі команди або запиту без належної фільтрації, типізації чи екранування.

### Досліджувані CWE-категорії:
- **CWE-89 (SQL Injection):** Несанкціонована зміна логіки виконання SQL-запиту через конкатенацію вхідних рядків. Дозволяє зловмиснику обійти автентифікацію, прочитати конфіденційні дані з будь-яких таблиць або модифікувати базу даних.
- **CWE-78 (OS Command Injection):** Впровадження розділювачів команд операційної системи (`&`, `|`, `;`, `&&`) у виклики оболонки (`cmd.exe`, `powershell.exe`, `/bin/sh`). Дозволяє віддалено виконувати довільні системні команди з привілеями веб-сервера.
- **CWE-79 / CWE-80 (HTML Injection):** Впровадження довільних HTML-тегів у сторінку, що призводить до спотворення інтерфейсу (Defacement) або викрадення чутливих даних через фішинг.
- **CWE-93 (CRLF / SMTP Injection):** Розрив протокольних заголовків поштового сервера за допомогою символів переведення рядка (`\r\n`), що дає змогу зловмиснику додавати несанкціонованих отримувачів (`Bcc:`) та розсилати спам/фішинг від імені сервера.

---

## 2. Архітектурна реалізація у проєкті TechFix

У проєкті **TechFix Enterprise** модуль ін'єкцій реалізовано за принципом **Dual-Mode (подвійний режим)**:
1. `IInjectionService` / `InjectionService` у шарі `TechFix.Infrastructure`.
2. `A1_InjectionController` у шарі `TechFix.WebApi` (маршрут `/api/A1_Injection`).

### 2.1. SQL Injection: Вразливий код vs Захищене рішення

```csharp
// ❌ ВРАЗЛИВИЙ МЕТОД: Конкатенація неперевірених рядків у SQL-запит
public async Task<List<PartDto>> SearchPartsVulnerableSqlAsync(string query)
{
    var sql = $"SELECT Id, Name, Category, Price, StockQuantity FROM Parts WHERE Name LIKE '%{query}%'";
    return await _context.Database.SqlQueryRaw<PartDto>(sql).ToListAsync();
}

// ✅ ЗАХИЩЕНИЙ МЕТОД: Параметризований LINQ-запит EF Core
public async Task<List<PartDto>> SearchPartsSecureSqlAsync(string query)
{
    return await _context.Parts
        .AsNoTracking()
        .Where(p => EF.Functions.Like(p.Name, $"%{query}%"))
        .Select(p => new PartDto { ... })
        .ToListAsync();
}
```

### 2.2. OS Command Injection: Вразливий код vs Захищене рішення

```csharp
// ❌ ВРАЗЛИВИЙ МЕТОД: Прямий виклик оболонки cmd.exe із конкатенацією аргументів
var startInfo = new ProcessStartInfo("cmd.exe", $"/c ping -n 1 {hostOrIp}")
{
    RedirectStandardOutput = true,
    UseShellExecute = false
};

// ✅ ЗАХИЩЕНИЙ МЕТОД: Системний API System.Net.NetworkInformation.Ping без виклику командного процесора
using var pinger = new Ping();
var reply = await pinger.SendPingAsync(sanitizedIp, 2000);
```

---

## 3. Практична демонстрація у Swagger UI

Усі тести виконано на живому екземплярі бекенду на порту `5006`.

### 3.1. Загальний огляд ендпоінтів A1 Injection
![Огляд ендпоінтів A1](./screenshots/01_swagger_overview.png)
*Рис. 1. Зареєстровані методи тестування ін'єкцій у Swagger UI.*

### 3.2. Рядкова SQL-ін'єкція (SQLi String)
- **Уразливий запит (Payload: `' OR '1'='1`):**  
  Запит повертає всі запчастини з бази даних в обхід критеріїв пошуку.
  ![SQLi String Vulnerable](./screenshots/02_swagger_sqli_string_vulnerable.png)
  *Рис. 2. Уразлива відповідь: несанкціоноване вилучення всіх записів таблиці.*

- **Захищений запит:**  
  Спеціальні символи сприймаються як частина літерального тексту; ін'єкцію нейтралізовано.
  ![SQLi String Secure](./screenshots/03_swagger_sqli_string_secure.png)
  *Рис. 3. Захищена відповідь: безпечне параметризоване виконання.*

### 3.3. Числова SQL-ін'єкція (Numeric SQLi)
- **Уразливий запит (Payload: `1 OR 1=1`):**  
  ![Numeric SQLi Vulnerable](./screenshots/04_swagger_sqli_numeric_vulnerable.png)
  *Рис. 4. Обхід фільтра за числовим ідентифікатором.*

### 3.4. Впровадження команд ОС (OS Command Injection)
- **Уразливий виклик (Payload: `127.0.0.1 & whoami`):**  
  Оболонка `cmd.exe` виконує системну утиліту `whoami` та повертає поточного користувача Windows.
  ![Command Injection Vulnerable](./screenshots/05_swagger_os_command_vulnerable.png)
  *Рис. 5. Виконання сторонньої команди ОС на сервері.*

- **Захищений виклик:**  
  Використання C# API `Ping.SendPingAsync` без системної оболонки.
  ![Command Injection Secure](./screenshots/06_swagger_os_command_secure.png)
  *Рис. 6. Захищена діагностика через мережевий сокет.*

### 3.5. HTML-ін'єкція у відгуках
- **Уразливе збереження (Payload: `<h1>Hacked</h1>`):**  
  ![HTML Injection Vulnerable](./screenshots/07_swagger_smtp_crlf_vulnerable.png)
  *Рис. 7. Пряме збереження HTML-розмітки.*

- **Захищене збереження (HtmlEncoder):**  
  ![HTML Injection Secure](./screenshots/08_swagger_smtp_crlf_secure.png)
  *Рис. 8. Автоматичне контекстне екранування символів.*

---

## 4. Зведена таблиця результатів аудиту ін'єкцій

| Вектор ін'єкції | CWE | Тестове навантаження (Payload) | Уразливий стан | Захисний стан (Remediation) |
|---|---|---|---|---|
| **SQLi (Рядкова)** | CWE-89 | `' OR '1'='1` | Повний витік каталогу товарів | Параметризація EF Core LINQ |
| **SQLi (Числова)** | CWE-89 | `1 OR 1=1` | Обхід фільтрації замовлень | Сувора типізація `int id` |
| **OS Command** | CWE-78 | `127.0.0.1 & whoami` | Виконання команд у Windows | `System.Net.NetworkInformation.Ping` |
| **HTML Injection** | CWE-79 | `<h1>Знижка 90%</h1>` | Спотворення контенту сторінки | `HtmlEncoder.Default.Encode()` |
| **SMTP Injection** | CWE-93 | `test\r\nBcc: spy@evil.com` | Несанкціоноване додавання копії | Валідація поштових заголовків від CRLF |

---

## 5. Контрольні запитання та відповіді

1. **Що таке SQL-ін'єкція та які існують основні типи?**  
   SQL-ін'єкція — це несанкціонована зміна структури SQL-запиту через неперевірені дані. Розрізняють: In-band (Union-based, Error-based), Blind/Inferential (Boolean-based, Time-based) та Out-of-band SQLi.
2. **Чому параметризовані запити гарантують захист від SQLi?**  
   Параметризовані запити відділяють компіляцію SQL-інструкції від передачі даних. Параметри передаються СКБД як літеральні константи і ніколи не інтерпретуються як виконуваний код.
3. **Як запобігти Command Injection у .NET?**  
   Слід відмовитися від виклику командних оболонок (`cmd.exe`, `sh`). Необхідно використовувати спеціалізовані мовні API або суворо налаштовувати `ProcessStartInfo` із передачею масиву `ArgumentList` без `UseShellExecute = true`.

---
