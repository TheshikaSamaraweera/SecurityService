package com.democode.votingSystem.controller;

import com.democode.votingSystem.dto.LoginRequest;
import com.democode.votingSystem.dto.LoginResponse;
import com.democode.votingSystem.dto.RegisterRequest;
import com.democode.votingSystem.dto.RegisterResponse;
import com.democode.votingSystem.services.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {


    @Autowired
    private final AuthService authService;


    @PostMapping("/register")
    public RegisterResponse register(@RequestBody RegisterRequest request) {
        return authService.register(request);
    }

    @PostMapping("/login")
    public LoginResponse login(@RequestBody LoginRequest request) {
        return authService.login(request);
    }

    @GetMapping("/verify")
    public String verifyEmail(@RequestParam String token) {
        return authService.verifyEmail(token);
    }

}
