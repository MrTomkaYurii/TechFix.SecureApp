# Module 04: A5: Broken Access Control & IDOR

> Practical security guide, attack vector demonstration in Swagger UI, and remediation architecture for TechFix Enterprise (.NET 10).

---

## 1. Теоретичні відомості

Уразливості класу **OWASP Top 10 A5: Broken Access Control** виникають, коли політики авторизації на стороні сервера не забезпечують належного обмеження дій користувачів відповідно до їх прав та ролей:
- **CWE-639 (Insecure Direct Object References - IDOR):** Пряме використання числових або передбачуваних ідентифікаторів об'єктів бази даних (`/api/baskets/1`, `?orderId=105`) без перевірки того, чи належить запитуваний ресурс поточному автентифікованому користувачу (горизонтальне підвищення привілеїв).
- **CWE-284 (Improper Access Control / User Impersonation):** Довіра параметрам авторства, переданим у тілі запиту (наприклад, параметр `userId` у JSON), що дозволяє надсилати повідомлення або відгуки від імені керівництва чи інших осіб (спуфінг особи).
- **CWE-285 (Improper Authorization / Security through Obscurity):** Спроба захисту адміністративних розділів шляхом їх приховування з навігаційного меню замість серверної перевірки прав доступу на базі ролей (Role-Based Access Control, RBAC).

---

## 2. Архітектурна реалізація у проєкті TechFix

У системі **TechFix Enterprise** модуль контролю доступу представлено інтерфейсом `IAccessControlService`, сервісом `AccessControlService` та контролером `A5_AccessControlController`:
- **Contextual Ownership Validation:** Кожен запит до кошика або замовлення звіряє ідентифікатор власника `Basket.UserId` із клеймом користувача з перевіреного токена (`CurrentUserId`).
- **Запобігання спуфінгу:** Ідентифікатор автора суворо витягується з контексту автентифікації на сервері; клієнтське поле `userId` повністю ігнорується.
- **Рольова модель RBAC:** Адміністративні ресурси захищено перевіркою ролей (`Role == "Admin"`), повертаючи `403 Forbidden` для неавторизованих користувачів.

```csharp
// ❌ ВРАЗЛИВИЙ МЕТОД: Повертає будь-який кошик за запитаним ID
public async Task<BasketDto?> GetBasketVulnerableAsync(int basketId)
{
    return await _context.Baskets.Where(b => b.Id == basketId)...;
}

// ✅ ЗАХИЩЕНИЙ МЕТОД: Контекстна перевірка приналежності кошика
public async Task<BasketDto?> GetBasketSecureAsync(int basketId, int currentUserId)
{
    var basket = await _context.Baskets.FirstOrDefaultAsync(b => b.Id == basketId);
    if (basket == null || basket.UserId != currentUserId)
    {
        throw new SecurityAccessException("Access denied. You do not own this basket.");
    }
    return MapToDto(basket);
}
```

---

## 3. Практична демонстрація у Swagger UI

### 3.1. Загальний огляд ендпоінтів A5
![Огляд ендпоінтів A5](./screenshots/01_swagger_a5_overview.png)
*Рис. 1. Ендпоінти контролю доступу у Swagger UI.*

### 3.2. Горизонтальний IDOR: Доступ до чужих кошиків
- **Уразливий запит (Звичайний користувач читає кошик адміністратора #1):**  
  ![IDOR View Vulnerable](./screenshots/02_swagger_idor_basket_vulnerable.png)
  *Рис. 2. Уразливий доступ: несанкціоноване читання чужого кошика.*

- **Захищений запит:**  
  ![IDOR View Secure](./screenshots/03_swagger_idor_basket_secure.png)
  *Рис. 3. Захищена відповідь: 403 Forbidden через невідповідність власника.*

### 3.3. Горизонтальний IDOR: Модифікація вмісту чужого кошика
- **Уразливе додавання товару в кошик #1:**  
  ![IDOR Add Vulnerable](./screenshots/04_swagger_idor_item_add_vulnerable.png)
  *Рис. 4. Успішне підкидання товару в кошик іншого користувача.*

- **Захищене додавання:**  
  ![IDOR Add Secure](./screenshots/05_swagger_idor_item_add_secure.png)
  *Рис. 5. Блокування операції зміни чужих даних.*

### 3.4. Підміна авторства у відгуках (User Impersonation)
- **Уразливе створення відгуку від імені директора (UserId: 1):**  
  ![Impersonation Vulnerable](./screenshots/06_swagger_impersonation_feedback_vulnerable.png)
  *Рис. 6. Фальсифікація автора повідомлення.*

- **Захищене створення (Прив'язка до автентифікованого токена):**  
  ![Impersonation Secure](./screenshots/07_swagger_impersonation_feedback_secure.png)
  *Рис. 7. Авторство визначається виключно сервером.*

### 3.5. Безпека через невідомість (Security through Obscurity)
- **Уразливий прямий доступ до прихованого URL `/hidden-admin-data`:**  
  ![Obscurity Vulnerable](./screenshots/08_swagger_obscurity_admin_vulnerable.png)
  *Рис. 8. Витік списку персоналу та хешів паролів через відсутність серверної авторизації.*

- **Захищений ендпоінт з RBAC:**  
  ![Obscurity Secure](./screenshots/09_swagger_obscurity_admin_secure.png)
  *Рис. 9. Захист через RBAC: 403 Forbidden для ролей без прав адміністратора.*

---

## 4. Зведена таблиця результатів

| Вектор загрози | CWE | Тестові параметри | Уразлива поведінка | Захисне рішення |
|---|---|---|---|---|
| **IDOR (Читання)** | CWE-639 | `GET /basket/1` | Доступ до чужого кошика | Контекстна перевірка володіння |
| **IDOR (Зміна)** | CWE-639 | `POST /basket/1/items` | Зміна чужих товарів | Блокування маніпуляцій |
| **Підміна автора** | CWE-284 | `userId: 1` у тілі | Спуфінг особи автора | Взяття ID виключно з Claims |
| **Security by Obscurity** | CWE-285 | `GET /hidden-admin-data` | Витік службових даних | Рольова модель RBAC |

---

## 5. Звіти лабораторної роботи
- **Word:** [`Звіт_ЛР4_Томка_A5_Broken_Access_Control.docx`](file:///C:/OneDrive/ТНТУ%20ПУЛЮЯ/3%20семестр/Технології%20розробки%20захищеного%20програмного%20забезпечення/Лабораторна_робота_4/Звіт_ЛР4_Томка_A5_Broken_Access_Control.docx)
- **PDF:** [`Звіт_ЛР4_Томка_A5_Broken_Access_Control.pdf`](file:///C:/OneDrive/ТНТУ%20ПУЛЮЯ/3%20семестр/Технології%20розробки%20захищеного%20програмного%20забезпечення/Лабораторна_робота_4/Звіт_ЛР4_Томка_A5_Broken_Access_Control.pdf)
