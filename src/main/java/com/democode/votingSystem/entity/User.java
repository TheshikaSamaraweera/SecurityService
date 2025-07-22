package com.democode.votingSystem.entity;

import jakarta.persistence.*;
import lombok.*;

import java.util.Date;
import java.util.UUID;

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

    @Lob
    @Column(nullable = false)
    private String publicKey;

    @Lob
    @Column(nullable = false)
    private String encryptedPrivateKey;

    private String role; // "VOTER" or "ADMIN"

    private String mfaSecret; // null if MFA not enabled

    @Builder.Default
    private boolean isEmailVerified = false;

    private String emailVerificationToken;
    private Date emailVerificationExpiry;

}
