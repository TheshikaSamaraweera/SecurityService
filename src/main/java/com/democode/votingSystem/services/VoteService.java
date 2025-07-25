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

@Service
@RequiredArgsConstructor
public class VoteService {

    private final UserRepository userRepository;
    private final VoteRepository voteRepository;

    // Inject EA public key (for demo, read from DB or static config)
    private final String eaPublicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhJBat64Gu9kWXAX7EfbFEjHQkXvpZAldqIUSiYcWklhNvJHK1RHnD7qXTH9Gnn2U/6QrBQ1G+NaWyzHpRMQYbtMweMl5jqxpbHfpUg7HxGgNTfAEPjP3KroLu/1knoUYLNE1oyyIQTCEYy9K7sMIfzVYz1ZXkU59gMyJMORa8hDpcfUudffmc9FhKY1PRpe0ZrCTtDX1GXbA0OF9aIgNu3aqiYqZ6vDH0dAvYfkQ+dE3YWXqCz8yTTRHLK+op+Mbx2r8gBeqVAtWM2AEu2bRIlXCt6sZgTsPe90MiRcsNmnjr8AUWxMi67wUxzAw4sHQADu8dYoccBOYez1Fgu4URQIDAQAB" ; // paste your real key here

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

    // TODO: Implement this method to fetch the voter's public key
    private PublicKey getVoterPublicKey(UUID voterId) throws Exception {
        User user = userRepository.findById(voterId)
                .orElseThrow(() -> new RuntimeException("User not found"));
        return CryptoUtil.decodeRSAPublicKey(user.getPublicKey());
    }
}
