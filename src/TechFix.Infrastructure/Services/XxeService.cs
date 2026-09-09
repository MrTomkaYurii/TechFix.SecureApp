using System.Diagnostics;
using System.Xml;
using TechFix.Application.DTOs;
using TechFix.Application.Interfaces;

namespace TechFix.Infrastructure.Services;

public class XxeService : IXxeService
{
    // ==========================================
    // TASK 1: SIMPLE XXE INJECTION (FILE LEAK)
    // ==========================================

    public Task<XmlOrderParseResponseDto> ParseOrderXmlVulnerableAsync(string xmlContent)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            // ВРАЗЛИВИЙ ПАРСЕР XML (CWE-611: Improper Restriction of XML External Entity Reference)
            // АНТИПАТЕРН: Встановлення XmlUrlResolver активує небезпечне завантаження зовнішніх ресурсів
            var xmlDoc = new XmlDocument();
            xmlDoc.XmlResolver = new XmlUrlResolver();

            using var stringReader = new StringReader(xmlContent);
            using var xmlReader = XmlReader.Create(stringReader, new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Parse, // Дозволяє обробку DTD
                XmlResolver = new XmlUrlResolver()  // Дозволяє системний резолвер файлів та мережі
            });

            xmlDoc.Load(xmlReader);

            var customerName = xmlDoc.SelectSingleNode("//customerName")?.InnerText ?? "Unknown";
            var deviceModel = xmlDoc.SelectSingleNode("//deviceModel")?.InnerText ?? "Unknown";
            var problemDesc = xmlDoc.SelectSingleNode("//problemDescription")?.InnerText ?? "Unknown";

            sw.Stop();

            // Перевірка чи стався витік системного файлу
            string? leakedData = null;
            if (customerName.Contains("[fonts]") || customerName.Contains("[extensions]") ||
                customerName.Contains("for 16-bit app support") || customerName.Contains("root:"))
            {
                leakedData = customerName;
            }

            return Task.FromResult(new XmlOrderParseResponseDto
            {
                Success = true,
                Message = leakedData != null 
                    ? "УВАГА: Виявлено успішну експлуатацію XXE ін'єкції! Зміст системного файлу прочитано через зовнішню сутність &xxe;."
                    : "XML замовлення успішно опрацьовано вразливим парсером.",
                CustomerName = customerName,
                DeviceModel = deviceModel,
                ProblemDescription = problemDesc,
                LeakedData = leakedData,
                SecurityMode = "Vulnerable (DtdProcessing.Parse + XmlUrlResolver)",
                ExecutionTimeMs = sw.ElapsedMilliseconds
            });
        }
        catch (Exception ex)
        {
            sw.Stop();
            return Task.FromResult(new XmlOrderParseResponseDto
            {
                Success = false,
                Message = $"Помилка парсингу XML: {ex.Message}",
                SecurityMode = "Vulnerable",
                ExecutionTimeMs = sw.ElapsedMilliseconds
            });
        }
    }

    public Task<XmlOrderParseResponseDto> ParseOrderXmlSecureAsync(string xmlContent)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            // ЗАХИЩЕНА РЕАЛІЗАЦІЯ ПАРСИНГУ XML ЗА СТАНДАРТАМИ SECURE BY DESIGN
            // 1. DtdProcessing.Prohibit — повна заборона обробки Document Type Definition
            // 2. XmlResolver = null — блокування будь-якого зовнішнього резолвінгу сутностей
            // 3. MaxCharactersFromEntities = 0 — вимкнення розгортання сутностей
            var secureSettings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                MaxCharactersFromEntities = 0,
                MaxCharactersInDocument = 100000 // Захист від роздутих XML документів
            };

            using var stringReader = new StringReader(xmlContent);
            using var xmlReader = XmlReader.Create(stringReader, secureSettings);

            var xmlDoc = new XmlDocument();
            xmlDoc.Load(xmlReader);

            var customerName = xmlDoc.SelectSingleNode("//customerName")?.InnerText ?? "Unknown";
            var deviceModel = xmlDoc.SelectSingleNode("//deviceModel")?.InnerText ?? "Unknown";
            var problemDesc = xmlDoc.SelectSingleNode("//problemDescription")?.InnerText ?? "Unknown";

            sw.Stop();

            return Task.FromResult(new XmlOrderParseResponseDto
            {
                Success = true,
                Message = "XML замовлення успішно та безпечно опрацьовано захищеним XmlReader.",
                CustomerName = customerName,
                DeviceModel = deviceModel,
                ProblemDescription = problemDesc,
                SecurityMode = "Secure (DtdProcessing.Prohibit + XmlResolver = null)",
                ExecutionTimeMs = sw.ElapsedMilliseconds
            });
        }
        catch (XmlException ex) when (ex.Message.Contains("DTD is prohibited") || ex.Message.Contains("DtdProcessing"))
        {
            sw.Stop();
            return Task.FromResult(new XmlOrderParseResponseDto
            {
                Success = false,
                Message = "Security Alert: Спроба XXE-атаки успішно заблокована! Використання DTD та зовнішніх сутностей (SYSTEM/PUBLIC) суворо заборонено політикою безпеки сервера.",
                SecurityMode = "Secure (Exploit Blocked)",
                ExecutionTimeMs = sw.ElapsedMilliseconds
            });
        }
        catch (Exception ex)
        {
            sw.Stop();
            return Task.FromResult(new XmlOrderParseResponseDto
            {
                Success = false,
                Message = $"Помилка валідації безпечного XML: {ex.Message}",
                SecurityMode = "Secure",
                ExecutionTimeMs = sw.ElapsedMilliseconds
            });
        }
    }

    // ==========================================
    // TASK 2: REST FRAMEWORK XML CONTENT-TYPE
    // ==========================================

    public Task<XmlOrderParseResponseDto> ProcessRestXmlVulnerableAsync(string rawXml)
    {
        return ParseOrderXmlVulnerableAsync(rawXml);
    }

    public Task<XmlOrderParseResponseDto> ProcessRestXmlSecureAsync(string rawXml)
    {
        return ParseOrderXmlSecureAsync(rawXml);
    }

    // ==========================================
    // TASK 3: XML FILE UPLOAD PROCESSING
    // ==========================================

    public Task<XmlOrderParseResponseDto> ProcessUploadedXmlFileVulnerableAsync(string fileContent, string fileName)
    {
        return ParseOrderXmlVulnerableAsync(fileContent);
    }

    public Task<XmlOrderParseResponseDto> ProcessUploadedXmlFileSecureAsync(string fileContent, string fileName)
    {
        // Додаткова перевірка розширення та MIME-типу перед парсингом
        if (!fileName.EndsWith(".xml", StringComparison.OrdinalIgnoreCase))
        {
            return Task.FromResult(new XmlOrderParseResponseDto
            {
                Success = false,
                Message = "Security Policy Violation: Дозволено завантаження виключно файлів специфікацій з розширенням .xml",
                SecurityMode = "Secure"
            });
        }

        return ParseOrderXmlSecureAsync(fileContent);
    }

    // ==========================================
    // TASK 4: BLIND XXE / SSRF
    // ==========================================

    public Task<XmlOrderParseResponseDto> ProcessBlindXxeVulnerableAsync(string xmlContent)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            var xmlDoc = new XmlDocument();
            xmlDoc.XmlResolver = new XmlUrlResolver();

            using var stringReader = new StringReader(xmlContent);
            using var xmlReader = XmlReader.Create(stringReader, new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Parse,
                XmlResolver = new XmlUrlResolver()
            });

            xmlDoc.Load(xmlReader);
            sw.Stop();

            return Task.FromResult(new XmlOrderParseResponseDto
            {
                Success = true,
                Message = "Blind XXE виконано: парсер намагався надіслати зовнішній HTTP-запит (Out-Of-Band SSRF) за адресою, вказаною в SYSTEM сутності.",
                SecurityMode = "Vulnerable (OOB SSRF Initiated)",
                ExecutionTimeMs = sw.ElapsedMilliseconds
            });
        }
        catch (Exception ex)
        {
            sw.Stop();
            return Task.FromResult(new XmlOrderParseResponseDto
            {
                Success = false,
                Message = $"Blind XXE виконання (Out-of-Band запит згенеровано): {ex.Message}",
                SecurityMode = "Vulnerable",
                ExecutionTimeMs = sw.ElapsedMilliseconds
            });
        }
    }

    public Task<XmlOrderParseResponseDto> ProcessBlindXxeSecureAsync(string xmlContent)
    {
        return ParseOrderXmlSecureAsync(xmlContent);
    }

    // ==========================================
    // TASK 5: BILLION LAUGHS XML BOMB (DOS)
    // ==========================================

    public Task<XmlOrderParseResponseDto> ProcessXmlBombDosVulnerableAsync(string xmlBomb)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            // Небезпечне експоненційне розгортання вкладених сутностей (CWE-776: Billion Laughs Attack)
            var xmlDoc = new XmlDocument();
            xmlDoc.XmlResolver = new XmlUrlResolver();

            using var stringReader = new StringReader(xmlBomb);
            using var xmlReader = XmlReader.Create(stringReader, new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Parse,
                MaxCharactersFromEntities = 0 // 0 означає відсутність обмежень на розмір розгорнутих сутностей!
            });

            xmlDoc.Load(xmlReader);
            sw.Stop();

            var textSample = xmlDoc.DocumentElement?.InnerText ?? "";
            return Task.FromResult(new XmlOrderParseResponseDto
            {
                Success = true,
                Message = $"УВАГА: XML-бомбу успішно розгорнуто в пам'яті! Результуючий розмір символів: {textSample.Length}. Створено критичне навантаження на CPU та RAM.",
                SecurityMode = "Vulnerable (Denial of Service - Exponential Entity Expansion)",
                ExecutionTimeMs = sw.ElapsedMilliseconds
            });
        }
        catch (Exception ex)
        {
            sw.Stop();
            return Task.FromResult(new XmlOrderParseResponseDto
            {
                Success = false,
                Message = $"Billion Laughs спровокував виняток пам'яті/ресурсів: {ex.Message}",
                SecurityMode = "Vulnerable",
                ExecutionTimeMs = sw.ElapsedMilliseconds
            });
        }
    }

    public Task<XmlOrderParseResponseDto> ProcessXmlBombDosSecureAsync(string xmlBomb)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            // Безпечні налаштування: жорсткий ліміт на кількість символів з сутностей
            var secureSettings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit, // або обмеження MaxCharactersFromEntities = 1024
                XmlResolver = null,
                MaxCharactersFromEntities = 1024,
                MaxCharactersInDocument = 10000
            };

            using var stringReader = new StringReader(xmlBomb);
            using var xmlReader = XmlReader.Create(stringReader, secureSettings);

            var xmlDoc = new XmlDocument();
            xmlDoc.Load(xmlReader);
            sw.Stop();

            return Task.FromResult(new XmlOrderParseResponseDto
            {
                Success = true,
                Message = "XML опрацьовано безпечно.",
                SecurityMode = "Secure",
                ExecutionTimeMs = sw.ElapsedMilliseconds
            });
        }
        catch (XmlException ex)
        {
            sw.Stop();
            return Task.FromResult(new XmlOrderParseResponseDto
            {
                Success = false,
                Message = $"Security Alert: XML Bomb (Billion Laughs DoS) заблоковано! Виняток: {ex.Message}",
                SecurityMode = "Secure (DoS Neutralized)",
                ExecutionTimeMs = sw.ElapsedMilliseconds
            });
        }
    }
}
