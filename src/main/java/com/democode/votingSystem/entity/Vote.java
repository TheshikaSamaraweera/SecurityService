package com.democode.votingSystem.entity;

import jakarta.persistence.*;
import lombok.*;
import java.util.UUID;

@Entity
@Table(name = "votes")
@Getter @Setter
@NoArgsConstructor @AllArgsConstructor
@Builder
public class Vote {

    @Id
    @GeneratedValue
    private UUID id;

    private UUID voterId; // reference, but keep voter anonymous in results

    @Column(nullable = false, columnDefinition = "TEXT")
    private String encryptedVote; // Encrypted with EA's public key

    @Column(nullable = false, columnDefinition = "TEXT")
    private String signature; // Signed hash of vote

    @Column(unique = true)
    private String anonId; // Random UUID for anonymous reference

    private boolean validated = false; // For Phase 6

}
