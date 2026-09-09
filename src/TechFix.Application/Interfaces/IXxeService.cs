using TechFix.Application.DTOs;

namespace TechFix.Application.Interfaces;

public interface IXxeService
{
    // Task 1: Simple XXE Injection (Arbitrary file retrieval)
    Task<XmlOrderParseResponseDto> ParseOrderXmlVulnerableAsync(string xmlContent);
    Task<XmlOrderParseResponseDto> ParseOrderXmlSecureAsync(string xmlContent);

    // Task 2: Modern REST Framework XML Processing
    Task<XmlOrderParseResponseDto> ProcessRestXmlVulnerableAsync(string rawXml);
    Task<XmlOrderParseResponseDto> ProcessRestXmlSecureAsync(string rawXml);

    // Task 3: XML File Upload Processing
    Task<XmlOrderParseResponseDto> ProcessUploadedXmlFileVulnerableAsync(string fileContent, string fileName);
    Task<XmlOrderParseResponseDto> ProcessUploadedXmlFileSecureAsync(string fileContent, string fileName);

    // Task 4: Blind XXE / Out-of-band SSRF
    Task<XmlOrderParseResponseDto> ProcessBlindXxeVulnerableAsync(string xmlContent);
    Task<XmlOrderParseResponseDto> ProcessBlindXxeSecureAsync(string xmlContent);

    // Task 5: Denial of Service (Billion Laughs XML Bomb)
    Task<XmlOrderParseResponseDto> ProcessXmlBombDosVulnerableAsync(string xmlBomb);
    Task<XmlOrderParseResponseDto> ProcessXmlBombDosSecureAsync(string xmlBomb);
}
