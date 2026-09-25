# Module 06: A7: Cross-Site Scripting (XSS)

> Practical security guide, attack vector demonstration in Swagger UI, and remediation architecture for TechFix Enterprise (.NET 10).

---

## 1. Теоретичні відомості

Уразливості класу **OWASP Top 10 A7: Cross-Site Scripting (XSS)** виникають, коли веб-застосунок включає неперевірені дані у вихідну веб-сторінку без належної валідації чи екранування, що призводить до виконання шкідливого коду JavaScript у браузері користувача:
- **Reflected XSS (Відбитий XSS, CWE-79):** Шкідливий скрипт передається через параметри HTTP-запиту (пошуковий рядок) і негайно відображається у відповіді сервера без збереження в БД.
- **Stored XSS (Збережений / Персистентний XSS, CWE-79):** Шкідливий скрипт зберігається на сервері (у базі даних відгуків, коментарів чи профілів) та виконується щоразу, коли будь-який користувач відкриває відповідну сторінку.
- **DOM-based XSS (XSS на рівні моделі DOM, CWE-79):** Вразливість виникає суворо на стороні клієнта в браузері, коли клієнтський скрипт читає дані з небезпечного джерела (`location.hash`, `window.location.search`) і передає їх у небезпечний приймач (sink: `window.location.href`, `eval()`, `element.innerHTML`).
- **Cookie Theft via XSS (CWE-1004):** Викрадення сесійних ідентифікаторів через доступ JavaScript до об'єкта `document.cookie` за відсутності прапорця `HttpOnly`.

---

## 2. Архітектурна реалізація у проєкті TechFix

У системі **TechFix Enterprise** модуль протидії XSS представлено інтерфейсом `IXssService`, бізнес-сервісом `XssService` та контролером `A7_XssController`:
- **Контекстне HTML-екранування:** Використання системного компонента `System.Text.Encodings.Web.HtmlEncoder.Default.Encode()` для нейтралізації спеціальних символів (`<`, `>`, `"`, `'`, `&`).
- **AntiXSS санітизація коментарів:** Видалення тегів `<script>`, псевдо-схем `javascript:` та обробників подій `onerror`, `onload`.
- **Захист DOM-перенаправлень:** Валідація цільових URL за білим списком допустимих протоколів (`http`, `https` або відносні шляхи).
- **HttpOnly Cookies:** Встановлення обов'язкових атрибутів безпеки: `HttpOnly = true`, `Secure = true`, `SameSite = SameSiteMode.Strict`.

```csharp
// ✅ КОНТЕКСТНЕ ЕКРАНУВАННЯ (HtmlEncoder)
var encodedQuery = HtmlEncoder.Default.Encode(query ?? string.Empty);
var rendered = $"<div class='search-results'><h3>Результати пошуку:</h3><span>{encodedQuery}</span></div>";

// ✅ ЗАХИЩЕНІ COOKIE З HTTPONLY
Response.Cookies.Append("TechFix_AuthSession", "secure_hmac_protected_token_888", new CookieOptions
{
    HttpOnly = true,
    Secure = true,
    SameSite = SameSiteMode.Strict
});
```

---

## 3. Практична демонстрація у Swagger UI

### 3.1. Загальний огляд ендпоінтів A7
![Огляд ендпоінтів A7](./screenshots/01_swagger_a7_overview.png)
*Рис. 1. Ендпоінти тестування міжсайтового скриптингу у Swagger UI.*

### 3.2. Відбитий XSS (Reflected XSS, CWE-79)
- **Уразливий пошук (Payload: `<script>alert('Reflected-XSS')</script>`):**  
  ![Reflected XSS Vulnerable](./screenshots/02_swagger_reflected_xss_vulnerable.png)
  *Рис. 2. Пряме впровадження активного скрипта у відповідь сервера.*

- **Захищений пошук:**  
  ![Reflected XSS Secure](./screenshots/03_swagger_reflected_xss_secure.png)
  *Рис. 3. Безпечне екранування символів у формат `&lt;script&gt;`.*

### 3.3. Збережений XSS (Stored XSS, CWE-79)
- **Уразливе збереження коментаря (Payload: `<img src=x onerror=alert(...)>`):**  
  ![Stored XSS Create Vulnerable](./screenshots/04_swagger_stored_xss_create_vulnerable.png)
  *Рис. 4. Персистентне збереження небезпечного тегу з обробником onerror.*

- **Уразливе читання списку коментарів:**  
  ![Stored XSS List Vulnerable](./screenshots/05_swagger_stored_xss_list_vulnerable.png)
  *Рис. 5. Трансляція шкідливого коду всім користувачам сервісу.*

- **Захищене збереження коментаря (AntiXSS Sanitization):**  
  ![Stored XSS Create Secure](./screenshots/06_swagger_stored_xss_create_secure.png)
  *Рис. 6. Автоматичне знешкодження тегів та обробників подій.*

- **Захищене читання списку:**  
  ![Stored XSS List Secure](./screenshots/07_swagger_stored_xss_list_secure.png)
  *Рис. 7. Чистий екранований список коментарів.*

### 3.4. DOM-based XSS (CWE-79)
- **Уразливе DOM-перенаправлення (Payload: `javascript:alert(document.cookie)`):**  
  ![DOM XSS Vulnerable](./screenshots/08_swagger_dom_xss_vulnerable.png)
  *Рис. 8. Виконання псевдо-схеми javascript: у клієнтському сінку window.location.*

- **Захищена оцінка схеми перенаправлення:**  
  ![DOM XSS Secure](./screenshots/09_swagger_dom_xss_secure.png)
  *Рис. 9. Валідація схеми за білим списком та безпечна заміна на root path '/'.*

### 3.5. Аудит кукі та блокування викрадення через HttpOnly (CWE-1004)
- **Уразливі Cookie (без HttpOnly):**  
  ![Cookie Vulnerable](./screenshots/10_swagger_cookie_theft_vulnerable.png)
  *Рис. 10. Доступність сесійного токена для викрадення через document.cookie.*

- **Захищені Cookie (HttpOnly=true):**  
  ![Cookie Secure](./screenshots/11_swagger_cookie_theft_secure.png)
  *Рис. 11. Повне блокування доступу до кукі з боку JavaScript.*

---

## 4. Зведена таблиця результатів

| Тип загрози XSS | CWE | Тестове навантаження | Уразлива реакція | Захисний стан (Remediation) |
|---|---|---|---|---|
| **Reflected XSS** | CWE-79 | `<script>alert('XSS')</script>` | Відбиття коду в DOM | `HtmlEncoder.Default.Encode()` |
| **Stored XSS** | CWE-79 | `<img onerror=alert(1)>` | Персистентне зараження | AntiXSS дезінфекція тегів |
| **DOM XSS** | CWE-79 | `javascript:alert(1)` | Виконання через `location` | Валідація схеми за білим списком |
| **Cookie Theft** | CWE-1004 | `document.cookie` | Крадіжка сесії жертви | `HttpOnly=true`, `SameSite=Strict` |

---

## 5. Звіти лабораторної роботи
- **Word:** [`Звіт_ЛР6_Томка_A7_XSS.docx`](file:///C:/OneDrive/ТНТУ%20ПУЛЮЯ/3%20семестр/Технології%20розробки%20захищеного%20програмного%20забезпечення/Лабораторна_робота_6/Звіт_ЛР6_Томка_A7_XSS.docx)
- **PDF:** [`Звіт_ЛР6_Томка_A7_XSS.pdf`](file:///C:/OneDrive/ТНТУ%20ПУЛЮЯ/3%20семестр/Технології%20розробки%20захищеного%20програмного%20забезпечення/Лабораторна_робота_6/Звіт_ЛР6_Томка_A7_XSS.pdf)
