package com.democode.votingSystem.controller;

import com.democode.votingSystem.dto.*;
import com.democode.votingSystem.repository.UserRepository;
import com.democode.votingSystem.services.AuthService;
import com.democode.votingSystem.services.MfaService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {


    @Autowired
    private final AuthService authService;
    private final MfaService mfaService;
    private  final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;


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

    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestParam String email) {
        var user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("Email not found"));

        String token = generateResetToken();
        user.setResetToken(token);
        userRepository.save(user);

        // TODO: Send token via email
        return ResponseEntity.ok(Map.of("resetToken", token)); // simulate for now
    }
    private String generateResetToken() {
        return UUID.randomUUID().toString();
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody ResetPasswordRequest request) {
        var user = userRepository.findByResetToken(request.token())
                .orElseThrow(() -> new RuntimeException("Invalid reset token"));

        user.setPasswordHash(passwordEncoder.encode(request.newPassword()));
        user.setResetToken(null); // invalidate token
        userRepository.save(user);

        return ResponseEntity.ok("Password reset successful.");
    }


}
