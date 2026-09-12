using TechFix.Application.DTOs;

namespace TechFix.Application.Interfaces;

public interface IAccessControlService
{
    // Task 4: Insecure Direct Object References (IDOR) - Accessing someone else's basket
    Task<AccessControlResponseDto> GetBasketVulnerableAsync(int basketId);
    Task<AccessControlResponseDto> GetBasketSecureAsync(int basketId, int currentUserId);

    // Task 6: Manipulating another user's basket items
    Task<AccessControlResponseDto> AddItemToBasketVulnerableAsync(int basketId, AddBasketItemRequestDto item);
    Task<AccessControlResponseDto> AddItemToBasketSecureAsync(int basketId, AddBasketItemRequestDto item, int currentUserId);

    // Task 5: Impersonation / Parameter Tampering in Customer Feedback
    Task<AccessControlResponseDto> SubmitFeedbackVulnerableAsync(FeedbackSubmitRequestDto request);
    Task<AccessControlResponseDto> SubmitFeedbackSecureAsync(FeedbackSubmitRequestDto request, int currentUserId);

    // Task 1 & 3: Missing Function Level Access Control / Relying on Obscurity
    Task<AccessControlResponseDto> GetHiddenAdminPortalVulnerableAsync();
    Task<AccessControlResponseDto> GetHiddenAdminPortalSecureAsync(string userRole);
}
