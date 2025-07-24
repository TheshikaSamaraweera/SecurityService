package com.democode.votingSystem.services;

import com.democode.votingSystem.dto.LoginRequest;
import com.democode.votingSystem.dto.LoginResponse;
import com.democode.votingSystem.dto.RegisterRequest;
import com.democode.votingSystem.dto.RegisterResponse;
import com.democode.votingSystem.entity.User;
import com.democode.votingSystem.repository.UserRepository;
import com.democode.votingSystem.util.CryptoUtil;
import com.democode.votingSystem.util.JwtUtil;
import com.democode.votingSystem.util.TotpUtil;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Date;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthService {

    @Autowired
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    private final JwtUtil jwtUtil;
    private final MailService mailService;

    @Value("${app.base-url}")
    private String baseUrl; // ✅ Remove `final`



    @Transactional
    public RegisterResponse register(RegisterRequest request) {
        try {
            // 1. Generate RSA keypair
            KeyPair keyPair = CryptoUtil.generateRSAKeyPair();

            // 2. Hash password
            String hashedPassword = passwordEncoder.encode(request.getPassword());

            // 3. Derive AES key and encrypt private key
            byte[] salt = CryptoUtil.generateSalt();
            SecretKey aesKey = CryptoUtil.deriveAESKeyPBKDF2(request.getPassword(), salt);

            byte[] iv = new byte[16];
            new SecureRandom().nextBytes(iv);

            String encryptedPrivateKey = CryptoUtil.encryptAES(
                    CryptoUtil.encodeKey(keyPair.getPrivate()), aesKey, iv);


            String token = UUID.randomUUID().toString();
            Date expiry = new Date(System.currentTimeMillis() + 1000 * 60 * 60); // 1 hour


            // ✅ Generate real MFA secret if enabled
            String mfaSecret = request.isMfaEnabled()
                    ? new GoogleAuthenticator().createCredentials().getKey()
                    : null;


            // 4. Store user
            User user = User.builder()
                    .name(request.getName())
                    .email(request.getEmail())
                    .passwordHash(hashedPassword)
                    .publicKey(CryptoUtil.encodeKey(keyPair.getPublic()))
                    .encryptedPrivateKey(encryptedPrivateKey)
                    .role(request.getRole())
                    .aesIv(CryptoUtil.encodeBytes(iv))
                    .aesSalt(CryptoUtil.encodeBytes(salt))
                    .mfaSecret(mfaSecret)
                    .emailVerificationToken(token)
                    .emailVerificationExpiry(expiry)
                    .isEmailVerified(false)
                    .build();

            userRepository.save(user);
            String link = baseUrl + "/api/auth/verify?token=" + token;
            mailService.sendVerificationEmail(request.getEmail(), link);
            return new RegisterResponse("Registration successful!");

        } catch (Exception e) {
            throw new RuntimeException("Registration failed: " + e.getMessage(), e);
        }
    }


    public LoginResponse login(LoginRequest request) {
        var user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            throw new RuntimeException("Invalid credentials");
        }

        if (!user.isEmailVerified()) {
            throw new RuntimeException("Email not verified");
        }

        if (user.getMfaSecret() != null) {
            if (request.getTotpCode() == null || !TotpUtil.verifyCode(user.getMfaSecret(), Integer.parseInt(request.getTotpCode()))) {
                throw new RuntimeException("Invalid TOTP code");
            }
        }

        // Generate JWT (we’ll implement JWT utility soon)
        String jwt = jwtUtil.generateToken(user.getEmail(), user.getRole());

        return new LoginResponse(jwt);
    }

    public String verifyEmail(String token) {
        var user = userRepository.findAll().stream()
                .filter(u -> token.equals(u.getEmailVerificationToken()))
                .findFirst()
                .orElseThrow(() -> new RuntimeException("Invalid verification token"));

        if (user.getEmailVerificationExpiry().before(new Date())) {
            throw new RuntimeException("Verification token expired");
        }

        user.setEmailVerified(true);
        user.setEmailVerificationToken(null);
        user.setEmailVerificationExpiry(null);
        userRepository.save(user);

        return "✅ Email verified successfully!";
    }


}