package com.democode.votingSystem.dto;

public record ResetPasswordRequest(
        String token,
        String newPassword
) {}