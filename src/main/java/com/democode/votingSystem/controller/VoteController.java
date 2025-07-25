package com.democode.votingSystem.controller;

import com.democode.votingSystem.dto.VoteRequest;
import com.democode.votingSystem.services.VoteService;
import com.democode.votingSystem.util.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.prepost.PreAuthorize;

import java.util.Map;

@RestController
@RequestMapping("/api/vote")
@RequiredArgsConstructor
public class VoteController {

    private final VoteService voteService;
    private final JwtUtil jwtUtil;

    @PostMapping("/submit")
    @PreAuthorize("hasRole('VOTER')")
    public ResponseEntity<?> submitVote(@RequestBody VoteRequest request, HttpServletRequest servletRequest) {
        try {
            String token = null;
            String encryptedPrivateKey = null;
            if (servletRequest.getCookies() != null) {
                for (var cookie : servletRequest.getCookies()) {
                    if ("token".equals(cookie.getName())) {
                        token = cookie.getValue();
                    }
                    if ("privateKey".equals(cookie.getName())) {
                        encryptedPrivateKey = cookie.getValue();
                    }
                }
            }

            if (token == null) {
                return ResponseEntity.status(401).body("Missing token");
            }
            if (encryptedPrivateKey == null) {
                return ResponseEntity.status(401).body("Missing private key. Please log in again.");
            }

            String email = jwtUtil.getEmailFromToken(token);

            // Decrypt private key from cookie
            var serverKey = com.democode.votingSystem.services.AuthService.getServerSideAESKey();
            var serverIv = com.democode.votingSystem.services.AuthService.getServerSideIV();
            String decryptedPrivateKeyPem = com.democode.votingSystem.util.CryptoUtil.decryptWithServerKey(encryptedPrivateKey, serverKey, serverIv);

            voteService.submitVote(request, email, decryptedPrivateKeyPem);

            return ResponseEntity.ok("Vote submitted successfully");
        } catch (Exception e) {
    e.printStackTrace(); // <-- This will print the full stack trace to your terminal
    return ResponseEntity.status(500).body("Vote failed: " + e.getMessage());
}
    }

    @GetMapping("/pending")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> getPendingVotes() {
        return ResponseEntity.ok(voteService.getPendingVotes());
    }

    @PostMapping("/validate/{anonId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> validateVote(@PathVariable String anonId) {
        try {
            voteService.validateVote(anonId);
            return ResponseEntity.ok("Vote validated successfully");
        } catch (Exception e) {
            return ResponseEntity.status(400).body("Validation failed: " + e.getMessage());
        }
    }

    @GetMapping("/bulletin")
    public ResponseEntity<?> getBulletinBoard() {
        // Only show validated votes
        var votes = voteService.getBulletinBoard();
        return ResponseEntity.ok(votes);
    }

    @PostMapping("/tally")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> tallyVotes(@RequestBody Map<String, String> body) {
        String eaPrivateKeyPem = body.get("eaPrivateKey");
        if (eaPrivateKeyPem == null || eaPrivateKeyPem.isEmpty()) {
            return ResponseEntity.badRequest().body("Missing eaPrivateKey in request body");
        }
        try {
            var tally = voteService.tallyVotes(eaPrivateKeyPem);
            return ResponseEntity.ok(tally);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Tallying failed: " + e.getMessage());
        }
    }
}
