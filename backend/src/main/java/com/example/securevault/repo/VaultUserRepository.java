package com.example.securevault.repo;

import com.example.securevault.domain.VaultUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface VaultUserRepository extends JpaRepository<VaultUser, Long> {
    Optional<VaultUser> findByUsername(String username);

    boolean existsByUsername(String username);
}
