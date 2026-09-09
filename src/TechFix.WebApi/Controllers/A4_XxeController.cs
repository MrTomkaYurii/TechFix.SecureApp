using Microsoft.AspNetCore.Mvc;
using TechFix.Application.DTOs;
using TechFix.Application.Interfaces;

namespace TechFix.WebApi.Controllers;

[ApiController]
[Route("api/[controller]")]
[Tags("OWASP A4: XML External Entities (XXE)")]
public class A4_XxeController : ControllerBase
{
    private readonly IXxeService _xxeService;

    public A4_XxeController(IXxeService xxeService)
    {
        _xxeService = xxeService;
    }

    // ==========================================================
    // 1. SIMPLE XXE INJECTION (FILE RETRIEVAL)
    // ==========================================================

    /// <summary>
    /// Вразливий парсер: DTD увімкнено (DtdProcessing.Parse + XmlUrlResolver), дозволяє зчитування системних файлів (win.ini, hosts).
    /// </summary>
    [HttpPost("parse-order/vulnerable")]
    public async Task<IActionResult> ParseOrderVulnerable([FromBody] XmlOrderParseRequestDto request)
    {
        var result = await _xxeService.ParseOrderXmlVulnerableAsync(request.XmlContent);
        return Ok(result);
    }

    /// <summary>
    /// Захищений парсер: повна заборона DTD (DtdProcessing.Prohibit, XmlResolver = null), блокування XXE.
    /// </summary>
    [HttpPost("parse-order/secure")]
    public async Task<IActionResult> ParseOrderSecure([FromBody] XmlOrderParseRequestDto request)
    {
        var result = await _xxeService.ParseOrderXmlSecureAsync(request.XmlContent);
        if (!result.Success && result.SecurityMode.Contains("Blocked"))
        {
            return BadRequest(result);
        }
        return Ok(result);
    }

    // ==========================================================
    // 2. MODERN REST FRAMEWORK XML INJECTION
    // ==========================================================

    /// <summary>
    /// Вразливий REST-ендпоінт: автоматична обробка XML тіла запиту з підвантаженням зовнішніх сутностей.
    /// </summary>
    [HttpPost("rest-xml/vulnerable")]
    [Consumes("application/xml", "text/xml")]
    public async Task<IActionResult> RestXmlVulnerable()
    {
        using var reader = new StreamReader(Request.Body);
        var rawXml = await reader.ReadToEndAsync();
        var result = await _xxeService.ProcessRestXmlVulnerableAsync(rawXml);
        return Ok(result);
    }

    /// <summary>
    /// Захищений REST-ендпоінт: безпечний парсинг XML з відключеними зовнішніми сутностями.
    /// </summary>
    [HttpPost("rest-xml/secure")]
    [Consumes("application/xml", "text/xml")]
    public async Task<IActionResult> RestXmlSecure()
    {
        using var reader = new StreamReader(Request.Body);
        var rawXml = await reader.ReadToEndAsync();
        var result = await _xxeService.ProcessRestXmlSecureAsync(rawXml);
        if (!result.Success) return BadRequest(result);
        return Ok(result);
    }

    // ==========================================================
    // 3. XML FILE UPLOAD (JUICE SHOP / WEBGOAT PATTERN)
    // ==========================================================

    /// <summary>
    /// Вразливе завантаження файлу: опрацювання вмісту завантаженого .xml файлу з виконанням DTD сутностей.
    /// </summary>
    [HttpPost("upload-spec/vulnerable")]
    public async Task<IActionResult> UploadSpecVulnerable(IFormFile file)
    {
        if (file == null || file.Length == 0) return BadRequest("Файл не передано.");
        using var reader = new StreamReader(file.OpenReadStream());
        var content = await reader.ReadToEndAsync();
        var result = await _xxeService.ProcessUploadedXmlFileVulnerableAsync(content, file.FileName);
        return Ok(result);
    }

    /// <summary>
    /// Захищене завантаження файлу: сувора санітизація та заборона DTD у завантажених XML специфікаціях.
    /// </summary>
    [HttpPost("upload-spec/secure")]
    public async Task<IActionResult> UploadSpecSecure(IFormFile file)
    {
        if (file == null || file.Length == 0) return BadRequest("Файл не передано.");
        using var reader = new StreamReader(file.OpenReadStream());
        var content = await reader.ReadToEndAsync();
        var result = await _xxeService.ProcessUploadedXmlFileSecureAsync(content, file.FileName);
        if (!result.Success) return BadRequest(result);
        return Ok(result);
    }

    // ==========================================================
    // 4. BLIND XXE & OUT-OF-BAND SSRF
    // ==========================================================

    /// <summary>
    /// Вразливий Blind XXE: генерація зовнішніх мережевих запитів (OOB SSRF) на контрольований сервер (WebWolf).
    /// </summary>
    [HttpPost("blind-oob/vulnerable")]
    public async Task<IActionResult> BlindXxeVulnerable([FromBody] BlindXxeRequestDto request)
    {
        var result = await _xxeService.ProcessBlindXxeVulnerableAsync(request.XmlContent);
        return Ok(result);
    }

    /// <summary>
    /// Захищений Blind XXE: повне блокування мережевих запитів з парсера через XmlResolver = null.
    /// </summary>
    [HttpPost("blind-oob/secure")]
    public async Task<IActionResult> BlindXxeSecure([FromBody] BlindXxeRequestDto request)
    {
        var result = await _xxeService.ProcessBlindXxeSecureAsync(request.XmlContent);
        if (!result.Success) return BadRequest(result);
        return Ok(result);
    }

    // ==========================================================
    // 5. BILLION LAUGHS ATTACK (DENIAL OF SERVICE)
    // ==========================================================

    /// <summary>
    /// Вразливий до DoS: експоненційне розгортання сутностей XML-бомби (Billion Laughs) без обмежень пам'яті.
    /// </summary>
    [HttpPost("billion-laughs-dos/vulnerable")]
    public async Task<IActionResult> BillionLaughsVulnerable([FromBody] XmlOrderParseRequestDto request)
    {
        var result = await _xxeService.ProcessXmlBombDosVulnerableAsync(request.XmlContent);
        return Ok(result);
    }

    /// <summary>
    /// Захист від DoS: обмеження MaxCharactersFromEntities = 1024 та блокування надмірних сутностей.
    /// </summary>
    [HttpPost("billion-laughs-dos/secure")]
    public async Task<IActionResult> BillionLaughsSecure([FromBody] XmlOrderParseRequestDto request)
    {
        var result = await _xxeService.ProcessXmlBombDosSecureAsync(request.XmlContent);
        if (!result.Success) return BadRequest(result);
        return Ok(result);
    }
}
