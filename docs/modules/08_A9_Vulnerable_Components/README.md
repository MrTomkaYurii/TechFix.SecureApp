# Module 08: A9: Using Components with Known Vulnerabilities

> Practical security guide, attack vector demonstration in Swagger UI, and remediation architecture for TechFix Enterprise (.NET 10).

---

## 1. Теоретичні відомості

Уразливість **OWASP Top 10 A9: Using Components with Known Vulnerabilities** (або A06 у версії OWASP Top 10:2021) виникає, коли програмна система використовує застарілі або непідтримувані сторонні бібліотеки, модулі та пакети з публічно відомими ідентифікаторами CVE (Common Vulnerabilities and Exposures):
- **CWE-1104 (Use of Unmaintained Third-Party Components):** Використання бібліотек, підтримка яких припинена вендором (End-of-Life).
- **CWE-1035 (Encounter of Vulnerable Component):** Пряма або транзитивна залежність від бібліотек із критичним рейтингом за шкалою CVSS (до 9.8–10.0), що дозволяє зловмисникам запускати готові експлойти з баз даних NVD / Exploit-DB без дослідження власного коду системи.
- **Software Supply Chain Security:** Захист ланцюжка постачання ПЗ вимагає створення та аудиту машиночитаного паспорта компонентів — **Software Bill of Materials (SBOM)** за стандартами **CycloneDX** або **SPDX**.

---

## 2. Архітектурна реалізація у проєкті TechFix

У проєкті **TechFix Enterprise** модуль аудиту компонентів представлено інтерфейсом `IComponentSecurityService`, сервісом `ComponentSecurityService` та контролером `A9_VulnerableComponentsController`:
- **Аудит застарілих компонентів:** Симуляція сканування legacy-середовища (.NET Core 3.1) сканерами Nikto та OpenVAS, де виявлено 4 критичні CVE:
  1. `Newtonsoft.Json 10.0.3` (CVE-2024-38063, CVSS 7.5 - DoS через вкладений JSON).
  2. `Microsoft.Data.SqlClient 2.0.0` (CVE-2021-34485, CVSS 7.8 - витік даних через обхід TLS).
  3. `System.Text.Encodings.Web 4.5.0` (CVE-2019-0820, CVSS 7.5 - DoS в енкодері).
  4. `log4net 1.2.10` (CVE-2018-1285, CVSS 9.8 - критичний XXE / SSRF).
- **Захищений стан .NET 10 LTS:** Повне оновлення до актуальних патчених пакетів (`Newtonsoft.Json 13.0.4`, `EF Core 10.0.12`, `Swashbuckle 7.3.1`) — 0 вразливостей, статус `Compliant`.
- **Генерація CycloneDX v1.5 SBOM:** Експорт структурованого паспорта компонентів із Package URL (purl), ліцензіями та хешами цілісності SHA-512.
- **Дорожня карта та CI/CD гейти:** Використання команд `dotnet list package --vulnerable` та політики `<NuGetAudit>true</NuGetAudit>`.

```csharp
// ✅ ГЕНЕРАЦІЯ CYCLONEDX SBOM
public Task<SbomReportDto> GenerateSbomSecureAsync()
{
    var sbom = new SbomReportDto
    {
        BomFormat = "CycloneDX",
        SpecVersion = "1.5",
        TargetComponent = "TechFix.Enterprise.SecureApp-v1.0",
        Components = new List<SbomComponentDto> { ... }
    };
    return Task.FromResult(sbom);
}
```

---

## 3. Практична демонстрація у Swagger UI

### 3.1. Загальний огляд ендпоінтів A9
![Огляд ендпоінтів A9](./screenshots/01_swagger_a9_overview.png)
*Рис. 1. Ендпоінти аудиту компонентів та SBOM у Swagger UI.*

### 3.2. Аудит вразливих застарілих залежностей
![Аудит вразливостей](./screenshots/02_swagger_audit_vulnerable.png)
*Рис. 2. Виявлення 4 небезпечних бібліотек із рейтингом CVSS до 9.8.*

### 3.3. Аудит сучасного захищеного стека .NET 10 LTS
![Аудит захищеного стека](./screenshots/03_swagger_audit_secure.png)
*Рис. 3. 0 відомих вразливостей та повна відповідність стандартам безпеки.*

### 3.4. Експорт Software Bill of Materials (CycloneDX SBOM)
![CycloneDX SBOM](./screenshots/04_swagger_sbom.png)
*Рис. 4. Структурований машинно-читаний паспорт компонентів ПЗ.*

### 3.5. Дорожня карта оновлення та політики CI/CD гейтів
![Remediation Plan](./screenshots/05_swagger_remediation_plan.png)
*Рис. 5. CLI-команди оновлення через dotnet add та політики NuGetAudit.*

---

## 4. Зведена таблиця результатів

| Компонент (Пакет) | Вразлива версія | CVE Ідентифікатор | CVSS | Захищена патчена версія |
|---|---|---|---|---|
| **Newtonsoft.Json** | 10.0.3 | CVE-2024-38063 | High (7.5) | 13.0.4 (Виправлено DoS) |
| **Microsoft.Data.SqlClient** | 2.0.0 | CVE-2021-34485 | High (7.8) | 10.0.12 Provider |
| **System.Text.Encodings.Web** | 4.5.0 | CVE-2019-0820 | High (7.5) | 10.0.0 Built-in |
| **log4net** | 1.2.10 | CVE-2018-1285 | Critical (9.8) | Замінено на штатне логування .NET |

---

## 5. Звіти лабораторної роботи
- **Word:** [`Звіт_ЛР8_Томка_A9_Vulnerable_Components.docx`](file:///C:/OneDrive/ТНТУ%20ПУЛЮЯ/3%20семестр/Технології%20розробки%20захищеного%20програмного%20забезпечення/Лабораторна_робота_8/Звіт_ЛР8_Томка_A9_Vulnerable_Components.docx)
- **PDF:** [`Звіт_ЛР8_Томка_A9_Vulnerable_Components.pdf`](file:///C:/OneDrive/ТНТУ%20ПУЛЮЯ/3%20семестр/Технології%20розробки%20захищеного%20програмного%20забезпечення/Лабораторна_робота_8/Звіт_ЛР8_Томка_A9_Vulnerable_Components.pdf)
