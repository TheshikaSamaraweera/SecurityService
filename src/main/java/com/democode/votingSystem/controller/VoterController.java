package com.democode.votingSystem.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@EnableMethodSecurity(prePostEnabled = true)
@RestController
@RequestMapping("/api/voter")
public class VoterController {

    @GetMapping("/dashboard")
    @PreAuthorize("hasRole('VOTER')")
    public ResponseEntity<String> voterDashboard() {
        return ResponseEntity.ok("Welcome Voter");
    }
}
