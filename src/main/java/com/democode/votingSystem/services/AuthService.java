package com.democode.votingSystem.services;

import com.democode.votingSystem.dto.RegisterRequest;
import com.democode.votingSystem.dto.RegisterResponse;
import com.democode.votingSystem.entity.User;
import com.democode.votingSystem.repository.UserRepository;
import com.democode.votingSystem.util.CryptoUtil;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.security.KeyPair;

@Service
@RequiredArgsConstructor
public class AuthService {

    @Autowired
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();


    @Transactional
    public RegisterResponse register(RegisterRequest request) {
        try {
            // 1. Generate RSA keypair
            KeyPair keyPair = CryptoUtil.generateRSAKeyPair();

            // 2. Hash password
            String hashedPassword = passwordEncoder.encode(request.getPassword());

            // 3. Derive AES key and encrypt private key
            SecretKey aesKey = CryptoUtil.getAESKeyFromPassword(request.getPassword());
            String encryptedPrivateKey = CryptoUtil.encryptAES(
                    CryptoUtil.encodeKey(keyPair.getPrivate()), aesKey);

            // 4. Store user
            User user = User.builder()
                    .name(request.getName())
                    .email(request.getEmail())
                    .passwordHash(hashedPassword)
                    .publicKey(CryptoUtil.encodeKey(keyPair.getPublic()))
                    .encryptedPrivateKey(encryptedPrivateKey)
                    .role(request.getRole())
                    .mfaSecret(request.isMfaEnabled() ? "TO_BE_GENERATED" : null)
                    .build();

            userRepository.save(user);
            return new RegisterResponse("Registration successful!");

        } catch (Exception e) {
            throw new RuntimeException("Registration failed: " + e.getMessage(), e);
        }
    }
}