using TechFix.Application.DTOs;

namespace TechFix.Application.Interfaces;

public interface IAuthenticationService
{
    // Task 1: Insecure Login Form & Weak Credential Storage
    Task<LoginResponseDto> LoginVulnerablePlaintextAsync(LoginRequestDto request);
    Task<LoginResponseDto> LoginSecureHashedAsync(LoginRequestDto request);

    // Task 2: Logout Management & Session Invalidation
    Task<string> LogoutVulnerableAsync(LogoutRequestDto request);
    Task<string> LogoutSecureAsync(LogoutRequestDto request);
    Task<object> CheckSessionVulnerableAsync(string sessionId);
    Task<object> CheckSessionSecureAsync(string token);

    // Task 3: Password Attacks & Brute-Force Protection
    Task<BruteForceResponseDto> LoginBruteForceVulnerableAsync(BruteForceLoginRequestDto request);
    Task<BruteForceResponseDto> LoginBruteForceSecureAsync(BruteForceLoginRequestDto request);

    // Task 4: Administrative Portals & Cookie Tampering
    Task<AdminPortalResponseDto> AccessAdminPortalVulnerableAsync(string? cookieHeader, string? roleHeader);
    Task<AdminPortalResponseDto> AccessAdminPortalSecureAsync(string? authHeader);

    // Task 5: Password Reset & Authentication Bypass
    Task<object> ResetPasswordVulnerableAsync(PasswordResetVulnerableDto request);
    Task<object> RequestPasswordResetTokenSecureAsync(string usernameOrEmail);
    Task<object> ResetPasswordSecureAsync(PasswordResetSecureRequestDto request);

    // Task 6: JWT Signature Stripping & Claim Tampering (alg: none)
    Task<object> GenerateSampleJwtAsync(string username, string role);
    Task<object> VerifyJwtVulnerableAsync(string token);
    Task<object> VerifyJwtSecureAsync(string token);

    // Task 7: Rainbow Tables & Password Hashing Algorithms
    List<RainbowHashDemoDto> GetRainbowTableDemonstration(string samplePassword);
}
