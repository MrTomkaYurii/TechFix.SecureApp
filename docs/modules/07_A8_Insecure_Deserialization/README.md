# Module 07: A8: Insecure Deserialization & ReDoS

> Practical security guide, attack vector demonstration in Swagger UI, and remediation architecture for TechFix Enterprise (.NET 10).

---

## 1. Теоретичні відомості

Уразливість **OWASP Top 10 A8: Insecure Deserialization** виникає, коли застосунок перетворює неперевірені серіалізовані дані у живі об'єкти пам'яті без належної перевірки їх структури, типів та цифрового підпису:
- **CWE-502 (Deserialization of Untrusted Data / Polymorphic Gadgets):** Використання налаштування `TypeNameHandling.All` у бібліотеці `Newtonsoft.Json`, що дозволяє зловмиснику вказати довільний тип класу у метаданих `$type` та інстанціювати шкідливі гаджети для віддаленого виконання коду (RCE).
- **CWE-400 (Uncontrolled Resource Consumption / ReDoS DoS):** Десеріалізація або виконання динамічних виразів, що містять регулярні вирази з катастрофічним бектрекінгом (`/((a+)+)b/`), що призводить до зависання робочих потоків веб-сервера.
- **CWE-565 / CWE-347 (Reliance on Cookies without Integrity / Missing Cryptographic Signature):** Зберігання серіалізованого стану користувацької сесії (ролі, привілеї) у відкритому кодуванні Base64 без цифрового підпису, що дає змогу зловмиснику самовільно змінити роль на `Admin` (підвищення привілеїв).

---

## 2. Архітектурна реалізація у проєкті TechFix

У системі **TechFix Enterprise** модуль протидії небезпечній десеріалізації реалізовано через контракт `IDeserializationService`, сервіс `DeserializationService` та контролер `A8_DeserializationController`:
- **Сувора типізація через System.Text.Json:** Відмова від використання `TypeNameHandling.All`. Безпечний рушій `System.Text.Json` повністю ігнорує токени `$type` та парсить виключно задекларовані властивості цільового DTO-класу.
- **Попередня валідація схеми:** Відхилення будь-яких запитів із метаданими або ознаками регулярних виразів до їх потрапляння до десеріалізатора.
- **Криптографічний захист сесій через HMAC-SHA256:** Серіалізований токен формується у форматі `Base64(Payload).Base64(HMAC-SHA256)`. При десеріалізації підпис перевіряється за допомогою стійкого до атак за часом методу `CryptographicOperations.FixedTimeEquals`.

```csharp
// ❌ ВРАЗЛИВА ПОЛІМОРФНА ДЕСЕРІАЛІЗАЦІЯ
var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };
var obj = JsonConvert.DeserializeObject(rawJson, settings); // Інстанціює будь-який $type!

// ✅ ЗАХИЩЕНА СТРОГО ТИПІЗОВАНА ДЕСЕРІАЛІЗАЦІЯ
var options = new System.Text.Json.JsonSerializerOptions { MaxDepth = 4 };
var items = System.Text.Json.JsonSerializer.Deserialize<List<OrderLineItemDto>>(rawJson, options);
```

---

## 3. Практична демонстрація у Swagger UI

### 3.1. Загальний огляд ендпоінтів A8
![Огляд ендпоінтів A8](./screenshots/01_swagger_a8_overview.png)
*Рис. 1. Ендпоінти десеріалізації та аудиту цілісності у Swagger UI.*

### 3.2. Поліморфні RCE-гаджети через $type (CWE-502)
- **Уразливе замовлення із викликом DiagnosticGadgetCommand:**  
  ![Gadget Vulnerable](./screenshots/02_swagger_polymorphic_gadget_vulnerable.png)
  *Рис. 2. Інстанціювання системного гаджета з виконанням системної команди.*

- **Захищена обробка легітимного замовлення:**  
  ![Strict Typed Secure](./screenshots/03_swagger_strict_typed_secure.png)
  *Рис. 3. Швидке та безпечне розбирання списку деталей через System.Text.Json.*

- **Захищене блокування спроби передачі $type:**  
  ![Gadget Blocked Secure](./screenshots/04_swagger_gadget_blocked_secure.png)
  *Рис. 4. Відхилення підозрілого payload шлюзом валідації.*

### 3.3. Атаки на відмову в обслуговуванні ReDoS / DoS (CWE-400)
- **Уразлива оцінка виразу /((a+)+)b/:**  
  ![ReDoS Vulnerable](./screenshots/05_swagger_redos_vulnerable.png)
  *Рис. 5. Блокування потоку на 250 мс через катастрофічний бектрекінг.*

- **Захищена оцінка виразу:**  
  ![ReDoS Secure](./screenshots/06_swagger_redos_secure.png)
  *Рис. 6. Миттєве відхилення небезпечного регулярного виразу.*

### 3.4. Підробка стану сесії та захист HMAC-SHA256 (CWE-565, CWE-347)
- **Генерація легітимного підписаного токена:**  
  ![Generate Signed Token](./screenshots/07_swagger_session_generate_signed.png)
  *Рис. 7. Створення токена з криптографічним підписом сервера.*

- **Уразливе відновлення непідписаного токена:**  
  ![Session Tamper Vulnerable](./screenshots/08_swagger_session_tamper_vulnerable.png)
  *Рис. 8. Успішне підвищення привілеїв до Administrator через зміну Base64.*

- **Захищене відновлення підробленого токена:**  
  ![Session Tamper Secure](./screenshots/09_swagger_session_tamper_secure.png)
  *Рис. 9. Виявлення підробки підпису та скасування сесії.*

- **Захищене відновлення легітимного токена:**  
  ![Session Valid Secure](./screenshots/10_swagger_session_valid_secure.png)
  *Рис. 10. Успішна верифікація підпису HMAC-SHA256.*

---

## 4. Зведена таблиця результатів

| Вектор атаки | CWE | Тестовий payload | Уразливий стан | Захисний стан (Remediation) |
|---|---|---|---|---|
| **Поліморфний RCE** | CWE-502 | `{"$type": "DiagnosticGadget..."}` | Довільна інстанціація класів | Строга типізація System.Text.Json |
| **ReDoS DoS** | CWE-400 | `/((a+)+)b/.test('aaa...')` | Блокування потоків сервера | Попередня валідація схеми |
| **Підробка сесії** | CWE-565 | Base64 з `Role: Admin` | Несанкціонований доступ Admin | Цифровий підпис HMAC-SHA256 |

---

## 5. Звіти лабораторної роботи
- **Word:** [`Звіт_ЛР7_Томка_A8_Insecure_Deserialization.docx`](file:///C:/OneDrive/ТНТУ%20ПУЛЮЯ/3%20семестр/Технології%20розробки%20захищеного%20програмного%20забезпечення/Лабораторна_робота_7/Звіт_ЛР7_Томка_A8_Insecure_Deserialization.docx)
- **PDF:** [`Звіт_ЛР7_Томка_A8_Insecure_Deserialization.pdf`](file:///C:/OneDrive/ТНТУ%20ПУЛЮЯ/3%20семестр/Технології%20розробки%20захищеного%20програмного%20забезпечення/Лабораторна_робота_7/Звіт_ЛР7_Томка_A8_Insecure_Deserialization.pdf)
