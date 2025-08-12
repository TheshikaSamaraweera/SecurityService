package com.democode.SecurityService.dto;

import lombok.Data;

@Data

public class RegisterResponse {
    private String message;

    public RegisterResponse(String message) {
        this.message = message;
    }

    public String getMessage() {
        return message;
    }




}
