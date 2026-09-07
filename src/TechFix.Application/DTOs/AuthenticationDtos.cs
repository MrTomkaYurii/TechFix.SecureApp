namespace TechFix.Application.DTOs;

public class LoginRequestDto
{
    public string UsernameOrEmail { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
}

public class LoginResponseDto
{
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
    public string? Token { get; set; }
    public string? SessionId { get; set; }
    public string? UserRole { get; set; }
    public string? SecurityMode { get; set; }
    public DateTime? ExpiresAt { get; set; }
}

public class LogoutRequestDto
{
    public string SessionId { get; set; } = string.Empty;
    public string? Token { get; set; }
}

public class BruteForceLoginRequestDto
{
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string ClientIp { get; set; } = "192.168.1.105";
}

public class BruteForceResponseDto
{
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
    public int AttemptNumber { get; set; }
    public bool IsLockedOut { get; set; }
    public int LockoutRemainingSeconds { get; set; }
    public string SecurityAdvice { get; set; } = string.Empty;
}

public class AdminPortalResponseDto
{
    public bool AccessGranted { get; set; }
    public string Message { get; set; } = string.Empty;
    public string? AuthenticatedAs { get; set; }
    public string? Role { get; set; }
    public object? ConfidentialData { get; set; }
}

public class PasswordResetVulnerableDto
{
    public string Username { get; set; } = string.Empty;
    public string? SecurityQuestion { get; set; }
    public string? SecurityAnswer { get; set; }
    public string NewPassword { get; set; } = string.Empty;
}

public class PasswordResetSecureRequestDto
{
    public string ResetToken { get; set; } = string.Empty;
    public string NewPassword { get; set; } = string.Empty;
}

public class JwtVerificationRequestDto
{
    public string Token { get; set; } = string.Empty;
}

public class RainbowHashDemoDto
{
    public string PlaintextPassword { get; set; } = string.Empty;
    public string Algorithm { get; set; } = string.Empty;
    public string Hash { get; set; } = string.Empty;
    public string? Salt { get; set; }
    public int Iterations { get; set; }
    public bool VulnerableToRainbowTables { get; set; }
    public string Explanation { get; set; } = string.Empty;
}
