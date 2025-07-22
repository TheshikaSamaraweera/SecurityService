package com.democode.votingSystem.controller;

import com.democode.votingSystem.dto.*;
import com.democode.votingSystem.services.AuthService;
import com.democode.votingSystem.services.MfaService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {


    @Autowired
    private final AuthService authService;
    private final MfaService mfaService;


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

    @PostMapping("/mfa/setup")
    public ResponseEntity<MfaSetup> setupMfa(@RequestParam String email) {
        return ResponseEntity.ok(mfaService.generateMfaSecret(email));
    }

}
