package com.democode.SecurityService.dto;

import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Data
public class RegisterRequest {
    private String name;
    private String email;
    private String password;
    private String role; // ADMIN or VOTER
    private boolean mfaEnabled;
}