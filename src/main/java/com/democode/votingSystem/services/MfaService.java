package com.democode.votingSystem.services;

import com.democode.votingSystem.dto.MfaSetup;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;
import org.springframework.stereotype.Service;

@Service
public class MfaService {

    private final GoogleAuthenticator gAuth = new GoogleAuthenticator();

    public MfaSetup generateMfaSecret(String email) {
        GoogleAuthenticatorKey key = gAuth.createCredentials();
        String secret = key.getKey();

        // You can use this URL in frontend to render QR
        String qrUrl = GoogleAuthenticatorQRGenerator.getOtpAuthURL("SecureVote", email, key);

        return new MfaSetup(secret, qrUrl);
    }

    public boolean verifyCode(String secret, int code) {
        return gAuth.authorize(secret, code);
    }
}