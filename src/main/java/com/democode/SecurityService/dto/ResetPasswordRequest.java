package com.democode.SecurityService.dto;

public record ResetPasswordRequest(
        String token,
        String newPassword
) {}