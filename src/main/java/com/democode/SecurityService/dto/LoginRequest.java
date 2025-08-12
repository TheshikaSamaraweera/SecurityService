package com.democode.SecurityService.dto;


import lombok.Data;

@Data
public class LoginRequest {
    private String email;
    private String password;
    private String totpCode; // Optional, only required if MFA is enabled
}
