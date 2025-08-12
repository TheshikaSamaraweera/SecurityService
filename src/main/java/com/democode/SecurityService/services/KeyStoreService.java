package com.democode.SecurityService.services;

import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

@Service
public class KeyStoreService {

    // Fetch EA public key from DB or config
    public PublicKey getElectionAuthorityPublicKey() {
        // Load from a file, config, or DB
        return null;
    }

    // Decrypt voter's private key (if stored encrypted)
    public PrivateKey decryptVoterPrivateKey(String encryptedPrivateKey) {
        // Decrypt using app’s AES key or password
        return null;
    }

    public String encryptVote(String vote, PublicKey eaPublicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, eaPublicKey);
        return Base64.getEncoder().encodeToString(cipher.doFinal(vote.getBytes()));
    }

    public String signVote(String voteHash, PrivateKey voterPrivateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(voterPrivateKey);
        signature.update(voteHash.getBytes());
        return Base64.getEncoder().encodeToString(signature.sign());
    }

    public String hash(String input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return Base64.getEncoder().encodeToString(digest.digest(input.getBytes()));
    }
}
