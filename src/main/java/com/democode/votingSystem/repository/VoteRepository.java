package com.democode.votingSystem.repository;

import com.democode.votingSystem.entity.Vote;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface VoteRepository extends JpaRepository<Vote, UUID> {
    boolean existsByVoterId(UUID voterId);
    Optional<Vote> findByAnonId(String anonId);
    List<Vote> findByValidatedFalse();
}
