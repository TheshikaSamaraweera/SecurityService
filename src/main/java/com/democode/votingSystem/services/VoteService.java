package com.democode.votingSystem.services;

import com.democode.votingSystem.dto.VoteRequest;
import com.democode.votingSystem.entity.User;
import com.democode.votingSystem.entity.Vote;
import com.democode.votingSystem.repository.UserRepository;
import com.democode.votingSystem.repository.VoteRepository;
import com.democode.votingSystem.util.CryptoUtil;
import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.security.*;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.Map;
import java.util.HashMap;

@Service
@RequiredArgsConstructor
public class VoteService {

    private final UserRepository userRepository;
    private final VoteRepository voteRepository;

    // Inject EA public key (for demo, read from DB or static config)
    private final String eaPublicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6Wy8P9sGaNNpdgO85UbuJ3xNo6kr3l8JMQfuEUPV3Zzr2I7XdNJtkeUf76y9hjkPkInnnKqkew5k/8Bad8CHH/ON/4RkAcDc5ntBPEMYOaXpR/KM2X3pQios50DqFNxN57skqEpCzbCPiZfHgfE73Y5v1eqNqwGAzHWrCvoctsV7ZguXkfBjNtNZQGHGHphJzjzx2FZzBixyncPZFGVOz3duPd9UEm67Trbw0/jI/MyLfaI9CnlERkjOTBr2sXZM3rKTYb7ZWZJc5qfIuB/NfLDb1wWjG+DuWviNpCqrgnfCcqj8aI6e/xtHeBo09kqqUWcjn2sjGpBIeV32OefDuwIDAQAB"; // paste your real key here
                        //eaPrivateKey = MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDpbLw/2wZo02l2A7zlRu4nfE2jqSveXwkxB+4RQ9XdnOvYjtd00m2R5R/vrL2GOQ+QieecqqR7DmT/wFp3wIcf843/hGQBwNzme0E8Qxg5pelH8ozZfelCKiznQOoU3E3nuySoSkLNsI+Jl8eB8Tvdjm/V6o2rAYDMdasK+hy2xXtmC5eR8GM201lAYcYemEnOPPHYVnMGLHKdw9kUZU7Pd24931QSbrtOtvDT+Mj8zIt9oj0KeURGSM5MGvaxdkzespNhvtlZklzmp8i4H818sNvXBaMb4O5a+I2kKquCd8JyqPxojp7/G0d4GjT2SqpRZyOfayMakEh5XfY558O7AgMBAAECggEABqzeNKHyAiUVmCiNii2n7tzOUuv/aKm6wg+yKQU8bvd8rnc7Rch6FgOBkSGVU+rQJ/fW9fMn/AA9NtZ3NS3TehWazcqpRNGRSk1jtVz31YzfPyL6ZdfaHVMbxfXkcSScXRBMK+c1F4Zr5xPo7S2LDZAetkqHCEkP4rOfaL4epxgFq6RBct9HquNBgaLNmwiAL3On628/eS0pdUQ4ORnXowniz1m5u2c/03TIw9QVP8yL73JbmtQqwkm62/Y2r9eq5zx0jIg4fCYANRuoHMcQ9BejtqKB/tReRqqY+xm0/vp6UelrS+OILXjWXGLQ0wznOdDNtk5wCDmrLDQfrp3B6QKBgQD/NXSExPz541DdG5jCLou6soncgHWtuQUIbJ7Dd4DcixiIq9y3a+SExx901IRy31VEjYCu0/FRzIi/NfRqYKY0FXiV3OzXgP8LY6LWnXcLpAqr+qLqhqjy24gj0xflUeEP1HGp1hept1cys8zCcPJKBIMg+W85IHfdvVoplLRBWQKBgQDqJf3Ndi6wFO/07ixyE94h+d5g4+MDqrmkpCfRVyEhQqMrPx2T9Y/lV4qF9C71cgXTldM8DIlqOqsGrr0rE2k1O8eq7TuAQkdHKUur27XiW1WOAUgFmT56ndk6qin1kAakLUnZHugj1emq1JQg+EINBDIjanoUo+wyeaKbB2XXMwKBgQDbuMIgrRjAbB1qwB+8zyYuDxjyZwbqEqlqn1nxICoptvfgc1cL9DBCwM0sYOvHmtBmvQ1Vd9QEgPwa4/ESxTNTFElFfXfL8puiyp2f+OJNe2ZUuu0YzecXcDq93Thtjxkd7+IMPu8Qh3Djjjl0DpoLb+cVtKs1m+aXWjcOJaErwQKBgAppOgnCsXy+0ZSQaoWAAKZ+F7czKsrk8nAxpFuYhi6Wae7oVYZYqtdFtzERlGzxbvTjeor2+70vcp9PcbXSnSDy0YP2HGktiUHOwkCX+lRgP0ObJvqov7BwCFKlckwq5UCzis8Oor/FKSihXxzALR+rChetClSUnVH5OpOuFoclAoGBAORSEtHMpHEFDhNnpXSiPsaq3jdx+amVwCrQ+hqyiUf8VxhP6tQzqnbGLn+gwvjy82lNAzokE3EcmNnTe5NPB22ET8HjGjoaaPuLgL6WYT8q9yKNVKXB1XAmxmmFVVsiMEeFrBCnV7tcl5NprFWL3VMr3NApEYQN8ekCj+jiKgOG
    public void submitVote(VoteRequest request, String voterEmail, String decryptedPrivateKeyPem) throws Exception {
        User user = userRepository.findByEmail(voterEmail)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (voteRepository.existsByVoterId(user.getId())) {
            throw new RuntimeException("You have already voted.");
        }

        // Use the decrypted private key PEM directly
        PrivateKey privateKey = CryptoUtil.decodeRSAPrivateKey(decryptedPrivateKeyPem);
        PublicKey eaPubKey = CryptoUtil.decodeRSAPublicKey(eaPublicKey);

        // 🔐 Encrypt vote with EA public key
        String encryptedVote = CryptoUtil.encryptRSA(request.getCandidate(), eaPubKey);

        // 🧾 Sign vote hash
        String voteHash = CryptoUtil.hashSHA256(encryptedVote);
        String signature = CryptoUtil.signSHA256(voteHash, privateKey);

        // 🪪 Generate anon ID
        String anonId = UUID.randomUUID().toString();

        Vote vote = Vote.builder()
                .voterId(user.getId())
                .encryptedVote(encryptedVote)
                .signature(signature)
                .anonId(anonId)
                .build();

        voteRepository.save(vote);
    }

    public List<Vote> getPendingVotes() {
        return voteRepository.findByValidatedFalse();
    }

    public boolean validateVote(String anonId) throws Exception {
        Vote vote = voteRepository.findByAnonId(anonId)
                .orElseThrow(() -> new RuntimeException("Vote not found"));
        // Check if already validated
        if (vote.isValidated()) {
            throw new RuntimeException("Vote already validated");
        }
        // Check for double voting
        if (voteRepository.existsByVoterId(vote.getVoterId())) {
            // This only checks if a vote exists, but since this is the same vote, it's fine
            // If you want to check for more than one vote, you could count by voterId
        }
        // Verify signature
        PublicKey voterPublicKey = getVoterPublicKey(vote.getVoterId()); // Implement this method
        String voteHash = CryptoUtil.hashSHA256(vote.getEncryptedVote());
        boolean valid = CryptoUtil.verifySHA256Signature(voteHash, vote.getSignature(), voterPublicKey);
        if (!valid) {
            throw new RuntimeException("Invalid signature");
        }
        vote.setValidated(true);
        voteRepository.save(vote);
        return true;
    }

    public List<BulletinBoardEntry> getBulletinBoard() {
        return voteRepository.findAll().stream()
                .filter(Vote::isValidated)
                .map(v -> new BulletinBoardEntry(v.getEncryptedVote(), v.getSignature(), v.getAnonId()))
                .toList();
    }

    public static class BulletinBoardEntry {
        public final String encryptedVote;
        public final String signature;
        public final String anonId;
        public BulletinBoardEntry(String encryptedVote, String signature, String anonId) {
            this.encryptedVote = encryptedVote;
            this.signature = signature;
            this.anonId = anonId;
        }
    }

    /**
     * Tally votes using the provided EA (ADMIN) private key.
     * The private key should be passed in the POST request body as JSON: { "eaPrivateKey": "..." }
     */
    public Map<String, Integer> tallyVotes(String eaPrivateKeyPem) throws Exception {
        PrivateKey eaPrivateKey = CryptoUtil.decodeRSAPrivateKey(eaPrivateKeyPem);
        List<Vote> validatedVotes = voteRepository.findAll().stream()
                .filter(Vote::isValidated)
                .toList();
        Map<String, Integer> tally = new HashMap<>();
        for (Vote vote : validatedVotes) {
            String candidate = CryptoUtil.decryptRSA(vote.getEncryptedVote(), eaPrivateKey);
            tally.put(candidate, tally.getOrDefault(candidate, 0) + 1);
        }
        return tally;
    }

    // TODO: Implement this method to fetch the voter's public key
    private PublicKey getVoterPublicKey(UUID voterId) throws Exception {
        User user = userRepository.findById(voterId)
                .orElseThrow(() -> new RuntimeException("User not found"));
        return CryptoUtil.decodeRSAPublicKey(user.getPublicKey());
    }
}
