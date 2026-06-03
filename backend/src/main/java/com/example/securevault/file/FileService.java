package com.example.securevault.file;

import com.example.securevault.domain.FileEntry;
import com.example.securevault.domain.TagEntry;
import com.example.securevault.domain.TagGram;
import com.example.securevault.domain.VaultUser;
import com.example.securevault.file.dto.FileDtos.FileContent;
import com.example.securevault.file.dto.FileDtos.FileView;
import com.example.securevault.file.dto.FileDtos.TagPayload;
import com.example.securevault.file.dto.FileDtos.TagView;
import com.example.securevault.file.dto.FileDtos.UploadRequest;
import com.example.securevault.repo.FileEntryRepository;
import com.example.securevault.repo.TagEntryRepository;
import com.example.securevault.repo.TagGramRepository;
import com.example.securevault.repo.VaultUserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class FileService {

    private final VaultUserRepository users;
    private final FileEntryRepository files;
    private final TagEntryRepository tags;
    private final TagGramRepository tagGrams;

    public FileService(VaultUserRepository users, FileEntryRepository files,
                       TagEntryRepository tags, TagGramRepository tagGrams) {
        this.users = users;
        this.files = files;
        this.tags = tags;
        this.tagGrams = tagGrams;
    }

    @Transactional
    public Long upload(Long ownerId, UploadRequest req) {
        VaultUser owner = users.getReferenceById(ownerId);
        FileEntry entry = files.save(
                new FileEntry(owner, req.metaCipher(), req.metaIv(), req.blobCipher(), req.blobIv()));

        List<TagPayload> payloads = req.tags() == null ? List.of() : req.tags();
        for (TagPayload t : payloads) {
            tags.save(new TagEntry(owner, entry, t.tagCipher(), t.tagIv()));
            for (String gram : t.grams()) {
                tagGrams.save(new TagGram(owner, entry, gram));
            }
        }
        return entry.getId();
    }

    @Transactional(readOnly = true)
    public List<FileView> listAll(Long ownerId) {
        List<FileEntry> entries = files.findByOwnerIdOrderByCreatedAtDesc(ownerId);
        return toViews(entries);
    }

    /**
     * Substring ("contains") search. Returns the owner's files whose tags
     * collectively contain <em>all</em> the supplied query trigrams — the
     * necessary condition for the file having a tag that contains every search
     * term. The match runs on the indexed {@code (owner_id, blindIndex)} column,
     * so it stays fast and never touches plaintext. It can over-match (trigrams
     * recombine), so the client confirms the real substring after decrypting.
     */
    @Transactional(readOnly = true)
    public List<FileView> search(Long ownerId, List<String> grams) {
        long distinctGrams = grams.stream().distinct().count();
        List<Long> fileIds = tagGrams.findFileIdsContainingAll(ownerId, grams, distinctGrams);
        if (fileIds.isEmpty()) {
            return List.of();
        }
        List<FileEntry> entries = files.findAllById(fileIds);
        entries.sort((a, b) -> b.getCreatedAt().compareTo(a.getCreatedAt()));
        return toViews(entries);
    }

    @Transactional(readOnly = true)
    public FileContent download(Long ownerId, Long fileId) {
        FileEntry entry = files.findByIdAndOwnerId(fileId, ownerId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "file not found"));
        return new FileContent(entry.getId(), entry.getMetaCipher(), entry.getMetaIv(),
                entry.getBlobCipher(), entry.getBlobIv());
    }

    @Transactional
    public void delete(Long ownerId, Long fileId) {
        FileEntry entry = files.findByIdAndOwnerId(fileId, ownerId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "file not found"));
        tagGrams.deleteByFileId(entry.getId());
        tags.deleteByFileId(entry.getId());
        files.delete(entry);
    }

    /** Assembles file summaries with their tags in one batched tag query. */
    private List<FileView> toViews(List<FileEntry> entries) {
        if (entries.isEmpty()) {
            return List.of();
        }
        List<Long> ids = entries.stream().map(FileEntry::getId).toList();
        Map<Long, List<TagView>> tagsByFile = tags.findByFileIdInOrderByIdAsc(ids).stream()
                .collect(Collectors.groupingBy(
                        t -> t.getFile().getId(),
                        Collectors.mapping(
                                t -> new TagView(t.getTagCipher(), t.getTagIv()),
                                Collectors.toList())));

        return entries.stream()
                .map(e -> new FileView(
                        e.getId(), e.getMetaCipher(), e.getMetaIv(), e.getCreatedAt(),
                        tagsByFile.getOrDefault(e.getId(), List.of())))
                .toList();
    }
}
