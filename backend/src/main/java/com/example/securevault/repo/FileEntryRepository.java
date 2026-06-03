package com.example.securevault.repo;

import com.example.securevault.domain.FileEntry;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface FileEntryRepository extends JpaRepository<FileEntry, Long> {
    List<FileEntry> findByOwnerIdOrderByCreatedAtDesc(Long ownerId);

    Optional<FileEntry> findByIdAndOwnerId(Long id, Long ownerId);
}
