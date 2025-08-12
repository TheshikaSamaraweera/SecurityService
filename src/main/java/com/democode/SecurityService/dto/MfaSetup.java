package com.democode.SecurityService.dto;

public record MfaSetup(String secret, String qrCodeUrl) {}