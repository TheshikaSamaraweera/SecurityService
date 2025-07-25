package com.democode.votingSystem.entity;

import jakarta.persistence.*;
import lombok.*;

import java.util.Date;
import java.util.UUID;
import java.security.*;
import java.util.Base64;

@Entity
@Table(name = "users")
@Getter @Setter
@NoArgsConstructor @AllArgsConstructor
@Builder
public class User {

    @Id
    @GeneratedValue
    private UUID id;

    private String name;

    @Column(unique = true, nullable = false)
    private String email;

    @Column(nullable = false)
    private String passwordHash;


    @Column(nullable = false, columnDefinition = "TEXT")
    private String publicKey;


    @Column(nullable = false, columnDefinition = "TEXT")
    private String encryptedPrivateKey;


    private String role; // "VOTER" or "ADMIN"

    private String mfaSecret; // null if MFA not enabled

    @Builder.Default
    private boolean isEmailVerified = false;

    private String emailVerificationToken;
    private Date emailVerificationExpiry;

    private String aesSalt;   // Base64
    private String aesIv;     // Base64

    @Column(name = "reset_token")
    private String resetToken;
    @Column(name = "reset_token_expire")
    private Date resetTokenExpiry;


    public static void main(String[] args) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();

        String privateKeyBase64 = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
        String publicKeyBase64 = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());

        System.out.println("Private Key (Base64):");
        System.out.println(privateKeyBase64);
        System.out.println();
        System.out.println("Public Key (Base64):");
        System.out.println(publicKeyBase64);
    }


}
