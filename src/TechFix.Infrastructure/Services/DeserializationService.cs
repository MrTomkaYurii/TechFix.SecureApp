namespace TechFix.Infrastructure.Services;

using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Newtonsoft.Json;
using TechFix.Application.DTOs;
using TechFix.Application.Interfaces;

public class DeserializationService : IDeserializationService
{
    private static readonly byte[] HmacKey = Encoding.UTF8.GetBytes("TechFix_HMAC_Deserialization_Key_2026_Secure!");

    public async Task<OrderSubmissionResultDto> ProcessOrderLinesVulnerableAsync(OrderSubmissionRawDto request)
    {
        var sw = Stopwatch.StartNew();
        var rawData = request.OrderLinesData?.Trim() ?? string.Empty;

        // 1. Check for JuiceShop style ReDoS / Function payload
        if (rawData.Contains("/((a+)+)b/") || rawData.Contains(".test(") || rawData.Contains("while(true)"))
        {
            // Simulate catastrophic backtracking or loop execution
            await Task.Delay(250); // Demonstrates noticeable CPU / Thread delay
            sw.Stop();
            return new OrderSubmissionResultDto
            {
                Success = false,
                Message = "VULNERABLE (CWE-400 / ReDoS): Server evaluated untrusted regex/function payload. Thread was blocked for 250ms due to catastrophic backtracking / unconstrained evaluation.",
                ParsedItemCount = 0,
                ProcessedType = "JavaScript / Regex Expression Evaluation",
                ExecutionTimeMs = sw.Elapsed.TotalMilliseconds,
                SecurityAuditNote = "CRITICAL: The server accepted a dynamic script string instead of structured data, leading to Denial of Service (DoS)."
            };
        }

        // 2. Insecure Polymorphic Deserialization using Newtonsoft.Json with TypeNameHandling.All
        try
        {
            var settings = new JsonSerializerSettings
            {
                TypeNameHandling = TypeNameHandling.All
            };

            var deserialized = JsonConvert.DeserializeObject(rawData, settings);

            sw.Stop();

            if (deserialized is DiagnosticGadgetCommand gadget)
            {
                return new OrderSubmissionResultDto
                {
                    Success = false,
                    Message = $"VULNERABLE (CWE-502 / RCE Gadget): Insecure deserialization triggered arbitrary type instantiation! Instantiated '{gadget.GetType().FullName}' with Target: '{gadget.ExecutableTarget}' and Args: '{gadget.Arguments}'.",
                    ParsedItemCount = 0,
                    ProcessedType = gadget.GetType().FullName ?? "Unknown",
                    ExecutionTimeMs = sw.Elapsed.TotalMilliseconds,
                    SecurityAuditNote = "EXPLOIT CONFIRMED: Attacker supplied $type metadata was executed during object graph reconstruction, enabling Remote Code Execution."
                };
            }

            if (deserialized is System.Collections.IEnumerable list)
            {
                int count = 0;
                foreach (var item in list) count++;
                return new OrderSubmissionResultDto
                {
                    Success = true,
                    Message = $"Processed {count} order line items via insecure deserializer.",
                    ParsedItemCount = count,
                    ProcessedType = deserialized.GetType().FullName ?? "List",
                    ExecutionTimeMs = sw.Elapsed.TotalMilliseconds,
                    SecurityAuditNote = "WARNING: TypeNameHandling.All is active. Although this payload was benign, the endpoint remains vulnerable to RCE gadgets."
                };
            }

            return new OrderSubmissionResultDto
            {
                Success = true,
                Message = $"Deserialized object of type {deserialized?.GetType().Name ?? "null"}.",
                ParsedItemCount = 1,
                ProcessedType = deserialized?.GetType().FullName ?? "object",
                ExecutionTimeMs = sw.Elapsed.TotalMilliseconds,
                SecurityAuditNote = "WARNING: Insecure deserialization endpoint executed."
            };
        }
        catch (Exception ex)
        {
            sw.Stop();
            return new OrderSubmissionResultDto
            {
                Success = false,
                Message = $"Deserialization error: {ex.Message}",
                ParsedItemCount = 0,
                ProcessedType = "Failed",
                ExecutionTimeMs = sw.Elapsed.TotalMilliseconds,
                SecurityAuditNote = "Vulnerable parser encountered syntax error."
            };
        }
    }

    public async Task<OrderSubmissionResultDto> ProcessOrderLinesSecureAsync(OrderSubmissionRawDto request)
    {
        var sw = Stopwatch.StartNew();
        var rawData = request.OrderLinesData?.Trim() ?? string.Empty;

        // 1. Strict input validation and rejection of script/regex expressions
        if (rawData.StartsWith("/") || rawData.StartsWith("(") || rawData.Contains("function") || rawData.Contains("$type"))
        {
            sw.Stop();
            return new OrderSubmissionResultDto
            {
                Success = false,
                Message = "SECURED: Request rejected by security validator. Metadata tokens ('$type', 'function', regex literals) are strictly forbidden in business payloads.",
                ParsedItemCount = 0,
                ProcessedType = "Rejected By Schema Validator",
                ExecutionTimeMs = sw.Elapsed.TotalMilliseconds,
                SecurityAuditNote = "SAFE: Insecure deserialization and ReDoS attempts neutralized at API gateway."
            };
        }

        // 2. Safe Typed Deserialization with System.Text.Json (ignoring polymorphic attributes)
        try
        {
            var options = new System.Text.Json.JsonSerializerOptions
            {
                AllowTrailingCommas = false,
                MaxDepth = 4, // Prevents Billion Laughs / recursion DoS
                PropertyNameCaseInsensitive = true
            };

            var items = System.Text.Json.JsonSerializer.Deserialize<List<OrderLineItemDto>>(rawData, options);
            await Task.CompletedTask;
            sw.Stop();

            return new OrderSubmissionResultDto
            {
                Success = true,
                Message = $"Successfully validated and processed {items?.Count ?? 0} order items.",
                ParsedItemCount = items?.Count ?? 0,
                ProcessedType = "System.Collections.Generic.List<OrderLineItemDto> (Strict DTO)",
                ExecutionTimeMs = sw.Elapsed.TotalMilliseconds,
                SecurityAuditNote = "SECURED: Strongly-typed deserialization using System.Text.Json. Polymorphic gadget chains and $type overrides are completely ignored."
            };
        }
        catch (System.Text.Json.JsonException ex)
        {
            sw.Stop();
            return new OrderSubmissionResultDto
            {
                Success = false,
                Message = $"JSON schema validation error: {ex.Message}",
                ParsedItemCount = 0,
                ProcessedType = "Invalid JSON",
                ExecutionTimeMs = sw.Elapsed.TotalMilliseconds,
                SecurityAuditNote = "SECURED: Non-conforming payloads safely rejected without code execution."
            };
        }
    }

    public SessionStateResultDto RestoreSessionVulnerable(string serializedPayloadBase64)
    {
        try
        {
            var json = Encoding.UTF8.GetString(Convert.FromBase64String(serializedPayloadBase64));
            var session = JsonConvert.DeserializeObject<SessionTokenPayloadDto>(json);

            if (session == null)
            {
                return new SessionStateResultDto { Success = false, SecurityStatus = "Invalid payload" };
            }

            bool isPrivilegeEscalation = session.Role.Equals("Admin", StringComparison.OrdinalIgnoreCase) || session.IsAdmin;

            return new SessionStateResultDto
            {
                Success = true,
                UserId = session.UserId,
                Username = session.Username,
                Role = session.Role,
                IsAdmin = session.IsAdmin,
                IsSignatureVerified = false,
                SecurityStatus = isPrivilegeEscalation
                    ? "VULNERABLE (CWE-565): Privilege Escalation successful! Tampered Base64 token accepted without cryptographic signature check. User gained Administrator role."
                    : "VULNERABLE: Unsigned token accepted. Any client can modify role/permissions before Base64 encoding."
            };
        }
        catch (Exception ex)
        {
            return new SessionStateResultDto
            {
                Success = false,
                SecurityStatus = $"Failed to restore session: {ex.Message}"
            };
        }
    }

    public SessionStateResultDto RestoreSessionSecure(string signedPayload)
    {
        // Expected format: Base64(Json).Base64(HmacSignature)
        var parts = signedPayload.Split('.');
        if (parts.Length != 2)
        {
            return new SessionStateResultDto
            {
                Success = false,
                IsSignatureVerified = false,
                SecurityStatus = "SECURED (Rejected): Invalid token format. Missing HMAC signature part."
            };
        }

        try
        {
            var rawJsonBytes = Convert.FromBase64String(parts[0]);
            var expectedSignature = Convert.FromBase64String(parts[1]);

            using var hmac = new HMACSHA256(HmacKey);
            var computedSignature = hmac.ComputeHash(rawJsonBytes);

            if (!CryptographicOperations.FixedTimeEquals(computedSignature, expectedSignature))
            {
                return new SessionStateResultDto
                {
                    Success = false,
                    IsSignatureVerified = false,
                    SecurityStatus = "SECURED (Security Alert): Cryptographic signature mismatch! Token tampering detected (CWE-347). Session restoration aborted."
                };
            }

            var json = Encoding.UTF8.GetString(rawJsonBytes);
            var session = System.Text.Json.JsonSerializer.Deserialize<SessionTokenPayloadDto>(json);

            return new SessionStateResultDto
            {
                Success = true,
                UserId = session?.UserId ?? 0,
                Username = session?.Username ?? "Unknown",
                Role = session?.Role ?? "User",
                IsAdmin = session?.IsAdmin ?? false,
                IsSignatureVerified = true,
                SecurityStatus = "SECURED: Cryptographic HMAC-SHA256 signature verified with constant-time equality check. Session authenticity and integrity guaranteed."
            };
        }
        catch (Exception ex)
        {
            return new SessionStateResultDto
            {
                Success = false,
                SecurityStatus = $"SECURED (Rejected): Token decoding error: {ex.Message}"
            };
        }
    }

    public string GenerateValidSignedSession(int userId, string username, string role)
    {
        var session = new SessionTokenPayloadDto
        {
            UserId = userId,
            Username = username,
            Role = role,
            IsAdmin = role.Equals("Admin", StringComparison.OrdinalIgnoreCase),
            ValidUntil = DateTime.UtcNow.AddHours(4)
        };

        var json = System.Text.Json.JsonSerializer.Serialize(session);
        var jsonBytes = Encoding.UTF8.GetBytes(json);

        using var hmac = new HMACSHA256(HmacKey);
        var signature = hmac.ComputeHash(jsonBytes);

        var part1 = Convert.ToBase64String(jsonBytes);
        var part2 = Convert.ToBase64String(signature);

        return $"{part1}.{part2}";
    }
}
