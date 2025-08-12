package com.democode.SecurityService.services;

import com.democode.SecurityService.dto.MfaSetup;
import com.democode.SecurityService.repository.UserRepository;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class MfaService {

    private final UserRepository userRepository;
    private final GoogleAuthenticator gAuth = new GoogleAuthenticator();

    public MfaSetup generateMfaSecret(String email) {
        GoogleAuthenticatorKey key = gAuth.createCredentials();
        String secret = key.getKey();

        // You can use this URL in frontend to render QR
        String qrUrl = GoogleAuthenticatorQRGenerator.getOtpAuthURL("SecureVote", email, key);

        // ✅ Save the secret in DB
        userRepository.findByEmail(email).ifPresent(user -> {
            user.setMfaSecret(secret);
            userRepository.save(user);
        });

        return new MfaSetup(secret, qrUrl);
    }

    public boolean verifyCode(String secret, int code) {
        return gAuth.authorize(secret, code);
    }
}