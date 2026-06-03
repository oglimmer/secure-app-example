package com.example.securevault.repo;

import com.example.securevault.domain.TagEntry;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Collection;
import java.util.List;

public interface TagEntryRepository extends JpaRepository<TagEntry, Long> {

    List<TagEntry> findByFileIdInOrderByIdAsc(Collection<Long> fileIds);

    void deleteByFileId(Long fileId);
}
