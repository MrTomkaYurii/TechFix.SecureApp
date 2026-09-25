# Module 09: A10: Insufficient Logging and Monitoring

> Practical security guide, attack vector demonstration in Swagger UI, and remediation architecture for TechFix Enterprise (.NET 10).

---

## 1. Теоретичні відомості

Уразливість **OWASP Top 10 A10: Insufficient Logging and Monitoring** (A09 у версії OWASP Top 10:2021) виникає, коли система не фіксує критичні події безпеки, не забезпечує цілісність записів або не має засобів оперативного реагування на аномалії:
- **CWE-117 (Improper Output Handling for Logs / CRLF Log Injection):** Впровадження символів переведення рядка (`\r\n` або `%0d%0a`) у вхідні поля, що записуються в текстові журнали, що дозволяє зловмисникові підробляти записи в журналі (Log Forgery / Spoofing) або маскувати власну активність.
- **CWE-778 (Insufficient Logging / Missing Audit Trail):** Проведення критичних фінансових чи адміністративних операцій (повернення грошей, скидання паролів, зміна привілеїв) без запису в журнал аудиту («приховані операції»).
- **CWE-392 (Failure to Alert on Security Anomalies):** Відсутність порогового моніторингу невдалих спроб автентифікації, що дозволяє зловмиснику непомітно проводити підбір паролів (Brute-Force) без сповіщення аналітиків SOC або систем SIEM.

---

## 2. Архітектурна реалізація у проєкті TechFix

У проєкті **TechFix Enterprise** модуль аудиту та моніторингу реалізовано через контракт `ILoggingMonitoringService`, сервіс `LoggingMonitoringService` та контролер `A10_LoggingMonitoringController`:
- **Санітизація та структуроване JSON-логування:** Заміна символів переведення рядка на нейтральні знаки `_` та запис подій у форматі структурованої телеметрії JSON, що унеможливлює розрив рядків.
- **Незмінний журнал аудиту (Immutable Audit Trail):** Фіксація кожної фінансової транзакції із обов'язковим присвоєнням наскрізного ідентифікатора `CorrelationId`, клієнтської IP-адреси, точної мітки часу UTC та статусу.
- **Порогова детекція аномалій (SIEM Alerting):** Автоматичне відстеження невдалих спроб входу; при досягненні 3 невдалих спроб система генерує тривогу високого рівня `BRUTE_FORCE_DETECTED` та формує машиночитане сповіщення для SIEM.

```csharp
// ✅ САНІТИЗАЦІЯ CRLF ТА СТРУКТУРОВАНЕ ЛОГУВАННЯ
var sanitizedUser = Regex.Replace(rawInput, @"[\r\n]", "_");
var structuredLog = $"{{\"timestamp\":\"{DateTime.UtcNow:O}\",\"level\":\"Warning\",\"event\":\"AuthenticationFailed\",\"user\":\"{sanitizedUser}\"}}";

// ✅ АВТОМАТИЗОВАНЕ СПОВІЩЕННЯ SIEM
if (failedAttempts >= 3)
{
    _auditEvents.Add(new SecurityAuditEventDto
    {
        CorrelationId = correlationId,
        EventType = "BRUTE_FORCE_DETECTED",
        Severity = "High",
        ClientIp = request.IpAddress
    });
}
```

---

## 3. Практична демонстрація у Swagger UI

### 3.1. Загальний огляд ендпоінтів A10
![Огляд ендпоінтів A10](./screenshots/01_swagger_a10_overview.png)
*Рис. 1. Ендпоінти логування та моніторингу у Swagger UI.*

### 3.2. Фальсифікація журналу (CRLF Log Injection, CWE-117)
- **Уразливе логування з підробкою запису:**  
  ![Log Injection Vulnerable](./screenshots/02_swagger_log_injection_vulnerable.png)
  *Рис. 2. Успішна підробка запису про вхід адміністратора через розрив рядка %0d%0a.*

- **Захищене структуроване логування:**  
  ![Log Injection Secure](./screenshots/03_swagger_log_injection_secure.png)
  *Рис. 3. Нейтралізація CRLF та структурований JSON запис.*

### 3.3. Повнота аудиту операцій (Missing Audit Trail, CWE-778)
- **Уразлива дія (Silent Refund):**  
  ![Financial Vulnerable](./screenshots/04_swagger_financial_vulnerable.png)
  *Рис. 4. Повернення коштів без фіксації у журналі безпеки.*

- **Захищена дія з незмінним аудитом:**  
  ![Financial Secure](./screenshots/05_swagger_financial_secure.png)
  *Рис. 5. Фіксація транзакції з CorrelationId та IP-адресою.*

### 3.4. Моніторинг та детекція аномалій (CWE-392)
- **Уразливий моніторинг (Тихі невдалі спроби входу):**  
  ![Login Probe Vulnerable](./screenshots/06_swagger_login_probe_vulnerable.png)
  *Рис. 6. Відсутність реакції на підозрілі спроби підбору паролів.*

- **Захищений моніторинг (Спрацювання тривоги SIEM):**  
  ![Login Probe Secure](./screenshots/07_swagger_login_probe_secure.png)
  *Рис. 7. Активація сповіщення BRUTE_FORCE_DETECTED при 3+ спробах.*

### 3.5. Журнал аудиту подій безпеки
![Audit Events List](./screenshots/08_swagger_audit_events_list.png)
*Рис. 8. Перегляд хронологічного журналу подій безпеки для форензики.*

---

## 4. Зведена таблиця результатів

| Сценарій аудиту | CWE | Вхідні дані | Уразливий стан | Захисний стан (Remediation) |
|---|---|---|---|---|
| **Log Injection** | CWE-117 | `admin%0d%0a[INFO] Success` | Фальсифікація журналу | Санітизація CRLF, JSON-формат |
| **Missing Audit** | CWE-778 | Повернення коштів $450.00 | Прихована операція без сліду | Незмінний аудит із CorrelationId та IP |
| **Anomaly Detection** | CWE-392 | Серія 3+ спроб входу | Повна відсутність сповіщень | Тривога `BRUTE_FORCE_DETECTED`, SIEM |

---

## 5. Звіти лабораторної роботи
- **Word:** [`Звіт_ЛР9_Томка_A10_Logging_and_Monitoring.docx`](file:///C:/OneDrive/ТНТУ%20ПУЛЮЯ/3%20семестр/Технології%20розробки%20захищеного%20програмного%20забезпечення/Лабораторна_робота_9/Звіт_ЛР9_Томка_A10_Logging_and_Monitoring.docx)
- **PDF:** [`Звіт_ЛР9_Томка_A10_Logging_and_Monitoring.pdf`](file:///C:/OneDrive/ТНТУ%20ПУЛЮЯ/3%20семестр/Технології%20розробки%20захищеного%20програмного%20забезпечення/Лабораторна_робота_9/Звіт_ЛР9_Томка_A10_Logging_and_Monitoring.pdf)
