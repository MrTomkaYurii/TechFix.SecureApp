namespace TechFix.Application.Interfaces;
using TechFix.Application.DTOs;

public interface IDeserializationService
{
    // Task 1 & 2: Order Lines Deserialization (Polymorphic Gadgets & DoS / ReDoS)
    Task<OrderSubmissionResultDto> ProcessOrderLinesVulnerableAsync(OrderSubmissionRawDto request);
    Task<OrderSubmissionResultDto> ProcessOrderLinesSecureAsync(OrderSubmissionRawDto request);

    // Task 3: Serialized Session State & Tampering
    SessionStateResultDto RestoreSessionVulnerable(string serializedPayloadBase64);
    SessionStateResultDto RestoreSessionSecure(string signedPayload);
    string GenerateValidSignedSession(int userId, string username, string role);
}
