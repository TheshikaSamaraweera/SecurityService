package com.democode.votingSystem.controller;

import com.democode.votingSystem.dto.*;
import com.democode.votingSystem.repository.UserRepository;
import com.democode.votingSystem.services.AuthService;
import com.democode.votingSystem.services.MailService;
import com.democode.votingSystem.services.MfaService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Date;
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
    private final MailService mailService;

    @Value("${app.base-url}")
    private String baseUrl;

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
        Date expiry = new Date(System.currentTimeMillis() + 15 * 60 * 1000); // 15 minutes

        user.setResetToken(token);
        user.setResetTokenExpiry(expiry);
        userRepository.save(user);

        String resetLink = baseUrl + "/reset-password?token=" + token;
        mailService.sendResetPasswordEmail(user.getEmail(), resetLink);

        return ResponseEntity.ok(Map.of("message", "Password reset link sent to email"));
    }

    private String generateResetToken() {
        return UUID.randomUUID().toString();
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody ResetPasswordRequest request) {
        var user = userRepository.findByResetToken(request.token())
                .orElseThrow(() -> new RuntimeException("Invalid reset token"));

        if (user.getResetTokenExpiry() == null || user.getResetTokenExpiry().before(new Date())) {
            throw new RuntimeException("Reset token has expired");
        }

        user.setPasswordHash(passwordEncoder.encode(request.newPassword()));
        user.setResetToken(null); // invalidate token
        user.setResetTokenExpiry(null);
        userRepository.save(user);

        return ResponseEntity.ok(Map.of("message", "Password reset successful."));
    }


}
