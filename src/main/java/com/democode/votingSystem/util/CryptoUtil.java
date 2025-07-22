package com.democode.votingSystem.util;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Base64;

public class CryptoUtil {

    // Generate RSA Keypair
    public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    // Generate AES Key from password (simple version, improve later with PBKDF2)
    public static SecretKey getAESKeyFromPassword(String password) throws NoSuchAlgorithmException {
        byte[] key = password.getBytes(); // TODO: Use PBKDF2 for stronger key derivation
        return new SecretKeySpec(key, 0, 16, "AES"); // AES-128
    }

    // Encrypt with AES
    public static String encryptAES(String plainText, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    // Decrypt with AES
    public static String decryptAES(String encryptedText, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decoded = Base64.getDecoder().decode(encryptedText);
        return new String(cipher.doFinal(decoded));
    }

    public static String encodeKey(Key key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }
}