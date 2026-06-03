package com.example.securevault.file;

import com.example.securevault.domain.FileAccess;
import com.example.securevault.domain.FileEntry;
import com.example.securevault.domain.TagEntry;
import com.example.securevault.domain.TagGram;
import com.example.securevault.domain.VaultUser;
import com.example.securevault.file.dto.FileDtos.Envelope;
import com.example.securevault.file.dto.FileDtos.FileContent;
import com.example.securevault.file.dto.FileDtos.FileView;
import com.example.securevault.file.dto.FileDtos.ShareRequest;
import com.example.securevault.file.dto.FileDtos.ShareView;
import com.example.securevault.file.dto.FileDtos.TagPayload;
import com.example.securevault.file.dto.FileDtos.TagView;
import com.example.securevault.file.dto.FileDtos.UploadRequest;
import com.example.securevault.repo.FileAccessRepository;
import com.example.securevault.repo.FileEntryRepository;
import com.example.securevault.repo.TagEntryRepository;
import com.example.securevault.repo.TagGramRepository;
import com.example.securevault.repo.VaultUserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class FileService {

    private final VaultUserRepository users;
    private final FileEntryRepository files;
    private final TagEntryRepository tags;
    private final TagGramRepository tagGrams;
    private final FileAccessRepository access;

    public FileService(VaultUserRepository users, FileEntryRepository files,
                       TagEntryRepository tags, TagGramRepository tagGrams,
                       FileAccessRepository access) {
        this.users = users;
        this.files = files;
        this.tags = tags;
        this.tagGrams = tagGrams;
        this.access = access;
    }

    @Transactional
    public Long upload(Long ownerId, UploadRequest req) {
        VaultUser owner = users.getReferenceById(ownerId);
        FileEntry entry = files.save(
                new FileEntry(owner, req.metaCipher(), req.metaIv(), req.blobCipher(), req.blobIv()));

        // The owner's own envelope: the DEK wrapped under their encKey (symmetric).
        access.save(new FileAccess(entry, owner, req.encryptedDek(), req.dekIv(),
                FileAccess.WrapType.SYMMETRIC, FileAccess.Role.OWNER));

        List<TagPayload> payloads = req.tags() == null ? List.of() : req.tags();
        for (TagPayload t : payloads) {
            tags.save(new TagEntry(owner, entry, t.tagCipher(), t.tagIv()));
            for (String gram : t.grams()) {
                tagGrams.save(new TagGram(owner, entry, gram));
            }
        }
        return entry.getId();
    }

    /** Every file the viewer can see — owned and shared-in — newest first. */
    @Transactional(readOnly = true)
    public List<FileView> listAll(Long viewerId) {
        return toViews(access.findByRecipientIdOrderByFileCreatedAtDesc(viewerId));
    }

    /**
     * Only the files shared <em>to</em> this user. Used for tag search over shared
     * files, which runs client-side: the recipient already holds the DEK for each
     * shared file (so tags are decryptable) and the shared set is bounded by what
     * was explicitly shared with them, so there's no need for — and no way to do —
     * a server-side blind-index match here (those indexes are owner-keyed).
     */
    @Transactional(readOnly = true)
    public List<FileView> listShared(Long viewerId) {
        return toViews(access.findByRecipientIdAndRoleOrderByFileCreatedAtDesc(
                viewerId, FileAccess.Role.READER.name()));
    }

    /**
     * Substring ("contains") search over the viewer's <em>own</em> files. The
     * blind indexes are keyed with the owner's indexKey, so only owned files can
     * be matched — shared-in files are intentionally not searchable (the owner's
     * index key never leaves their device, and a sharer cannot reproduce tokens
     * under the recipient's key). The trigram match is necessary-but-not-sufficient,
     * so the client confirms the real substring after decrypting.
     */
    @Transactional(readOnly = true)
    public List<FileView> search(Long ownerId, List<String> grams) {
        long distinctGrams = grams.stream().distinct().count();
        List<Long> fileIds = tagGrams.findFileIdsContainingAll(ownerId, grams, distinctGrams);
        if (fileIds.isEmpty()) {
            return List.of();
        }
        List<FileAccess> matched = access.findByRecipientIdAndFileIdIn(ownerId, fileIds);
        matched.sort(Comparator.comparing((FileAccess a) -> a.getFile().getCreatedAt()).reversed());
        return toViews(matched);
    }

    @Transactional(readOnly = true)
    public FileContent download(Long viewerId, Long fileId) {
        FileAccess a = access.findByFileIdAndRecipientId(fileId, viewerId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "file not found"));
        FileEntry entry = a.getFile();
        return new FileContent(entry.getId(), entry.getOwner().getUsername(),
                entry.getMetaCipher(), entry.getMetaIv(),
                entry.getBlobCipher(), entry.getBlobIv(), envelopeOf(a));
    }

    /** Only the owner may delete; this removes the file, its tags, and all envelopes. */
    @Transactional
    public void delete(Long ownerId, Long fileId) {
        FileEntry entry = files.findByIdAndOwnerId(fileId, ownerId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "file not found"));
        access.deleteByFileId(entry.getId());
        tagGrams.deleteByFileId(entry.getId());
        tags.deleteByFileId(entry.getId());
        files.delete(entry);
    }

    /**
     * Share a file with another user. Only the owner can share. The client has
     * already wrapped the DEK to the recipient's OpenPGP public key, so we just
     * store the resulting envelope. Re-sharing to the same recipient overwrites
     * their envelope (idempotent).
     */
    @Transactional
    public void share(Long ownerId, Long fileId, ShareRequest req) {
        FileEntry entry = files.findByIdAndOwnerId(fileId, ownerId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "file not found"));
        VaultUser recipient = users.findByUsername(req.recipientUsername())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "unknown recipient"));
        if (recipient.getId().equals(ownerId)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "cannot share a file with yourself");
        }
        // Idempotent re-share: drop any existing reader envelope first.
        access.deleteByFileIdAndRecipientId(entry.getId(), recipient.getId());
        access.save(new FileAccess(entry, recipient, req.encryptedDek(), null,
                FileAccess.WrapType.OPENPGP, FileAccess.Role.READER));
    }

    /** Who a file is shared with (readers only). Owner-only. */
    @Transactional(readOnly = true)
    public List<ShareView> listShares(Long ownerId, Long fileId) {
        files.findByIdAndOwnerId(fileId, ownerId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "file not found"));
        return access.findByFileId(fileId).stream()
                .filter(a -> FileAccess.Role.READER.name().equals(a.getRole()))
                .map(a -> new ShareView(a.getRecipient().getUsername(), a.getCreatedAt()))
                .toList();
    }

    /**
     * Revoke a recipient's access. Owner-only. Note this only removes server-side
     * access (and future reads) — it cannot retract a DEK the recipient has
     * already unwrapped. Cryptographic un-sharing would require rotating the DEK
     * and re-wrapping for the remaining recipients.
     */
    @Transactional
    public void revoke(Long ownerId, Long fileId, String recipientUsername) {
        files.findByIdAndOwnerId(fileId, ownerId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "file not found"));
        VaultUser recipient = users.findByUsername(recipientUsername)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "unknown recipient"));
        access.deleteByFileIdAndRecipientId(fileId, recipient.getId());
    }

    private static Envelope envelopeOf(FileAccess a) {
        return new Envelope(a.getEncryptedDek(), a.getDekIv(), a.getWrapType());
    }

    /**
     * Assembles file summaries from the viewer's access rows, batching the tag
     * lookup. Tags live on the file (encrypted under its DEK), so a shared reader
     * who unwraps the DEK can decrypt them just like the owner.
     */
    private List<FileView> toViews(List<FileAccess> accesses) {
        if (accesses.isEmpty()) {
            return List.of();
        }
        List<Long> fileIds = accesses.stream().map(a -> a.getFile().getId()).toList();
        Map<Long, List<TagView>> tagsByFile = tags.findByFileIdInOrderByIdAsc(fileIds).stream()
                .collect(Collectors.groupingBy(
                        t -> t.getFile().getId(),
                        Collectors.mapping(
                                t -> new TagView(t.getTagCipher(), t.getTagIv()),
                                Collectors.toList())));

        return accesses.stream()
                .map(a -> {
                    FileEntry e = a.getFile();
                    return new FileView(
                            e.getId(), e.getOwner().getUsername(), a.getRole(),
                            e.getMetaCipher(), e.getMetaIv(), e.getCreatedAt(),
                            envelopeOf(a),
                            tagsByFile.getOrDefault(e.getId(), List.of()));
                })
                .toList();
    }
}
