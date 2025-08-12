package com.democode.SecurityService.controller;

import com.democode.SecurityService.dto.*;
import com.democode.SecurityService.repository.UserRepository;
import com.democode.SecurityService.services.AuthService;
import com.democode.SecurityService.services.LoginAttemptService;
import com.democode.SecurityService.services.MailService;
import com.democode.SecurityService.services.MfaService;
import com.democode.SecurityService.util.JwtUtil;
import io.jsonwebtoken.Claims;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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
    private final JwtUtil jwtUtil;
    private final LoginAttemptService loginAttemptService;


    @Value("${app.base-url}")
    private String baseUrl;

    @PostMapping("/register")
    public RegisterResponse register(@RequestBody RegisterRequest request) {
        return authService.register(request);
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request, HttpServletResponse response) {
        String key = request.getEmail(); // or use IP address for IP-based protection

        // Check if login is blocked for this key
        if (loginAttemptService.isBlocked(key)) {
            return ResponseEntity.status(429).body(Map.of(
                    "error", "Too many failed login attempts. Please try again later."
            ));
        }

        try {
            // Call service to authenticate user and generate tokens
            LoginResponse loginResponse = authService.login(request);

            // Reset login attempts on success
            loginAttemptService.loginSucceeded(key);

            // Access Token cookie
            Cookie accessCookie = new Cookie("token", loginResponse.getToken());
            accessCookie.setHttpOnly(true);
            accessCookie.setSecure(true);
            accessCookie.setPath("/");
            accessCookie.setMaxAge(15 * 60); // 15 minutes

            // Refresh Token cookie
            Cookie refreshCookie = new Cookie("refresh", loginResponse.getRefreshToken());
            refreshCookie.setHttpOnly(true);
            refreshCookie.setSecure(true);
            refreshCookie.setPath("/");
            refreshCookie.setMaxAge(7 * 24 * 60 * 60); // 7 days

            response.addCookie(accessCookie);
            response.addCookie(refreshCookie);

            // Set encrypted private key cookie
            var user = userRepository.findByEmail(request.getEmail()).orElseThrow();
            String encryptedPrivateKeyForCookie = authService.getEncryptedPrivateKeyForCookie(user, request.getPassword());
            Cookie privateKeyCookie = new Cookie("privateKey", encryptedPrivateKeyForCookie);
            privateKeyCookie.setHttpOnly(true);
            privateKeyCookie.setSecure(true);
            privateKeyCookie.setPath("/");
            privateKeyCookie.setMaxAge(15 * 60); // 15 minutes (same as token)
            response.addCookie(privateKeyCookie);

            return ResponseEntity.ok(Map.of("message", "Login successful"));

        } catch (Exception ex) {
            // Record failed attempt
            loginAttemptService.loginFailed(key);
            return ResponseEntity.status(401).body(Map.of("error", "Invalid credentials"));
        }
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
    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletResponse response) {
        Cookie cookie = new Cookie("token", null);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(0); // Delete immediately

        response.addCookie(cookie);
        return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
    }



    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(HttpServletRequest request, HttpServletResponse response) {
        String refreshToken = null;

        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("refresh".equals(cookie.getName())) {
                    refreshToken = cookie.getValue();
                }
            }
        }

        if (refreshToken == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Refresh token missing"));
        }

        try {
            Claims claims = jwtUtil.validateToken(refreshToken);
            String email = claims.getSubject();
            String role = claims.get("role", String.class);

            String newAccessToken = jwtUtil.generateToken(email, role);

            Cookie newAccessCookie = new Cookie("token", newAccessToken);
            newAccessCookie.setHttpOnly(true);
            newAccessCookie.setSecure(true);
            newAccessCookie.setPath("/");
            newAccessCookie.setMaxAge(15 * 60);

            response.addCookie(newAccessCookie);

            return ResponseEntity.ok(Map.of("message", "Access token refreshed"));
        } catch (Exception e) {
            return ResponseEntity.status(401).body(Map.of("error", "Invalid refresh token"));
        }
    }



}
