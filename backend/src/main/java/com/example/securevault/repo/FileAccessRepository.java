package com.example.securevault.repo;

import com.example.securevault.domain.FileAccess;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

public interface FileAccessRepository extends JpaRepository<FileAccess, Long> {

    /** Every file the user can see (owned + shared-in), newest file first. */
    List<FileAccess> findByRecipientIdOrderByFileCreatedAtDesc(Long recipientId);

    /** This viewer's envelopes for a specific set of files (used by owner search). */
    List<FileAccess> findByRecipientIdAndFileIdIn(Long recipientId, Collection<Long> fileIds);

    /** This viewer's envelope for one file — present iff they have access. */
    Optional<FileAccess> findByFileIdAndRecipientId(Long fileId, Long recipientId);

    /** All envelopes for a file (the owner row + every share), for the "shared with" list. */
    List<FileAccess> findByFileId(Long fileId);

    boolean existsByFileIdAndRecipientId(Long fileId, Long recipientId);

    void deleteByFileId(Long fileId);

    void deleteByFileIdAndRecipientId(Long fileId, Long recipientId);
}
