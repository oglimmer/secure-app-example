package com.example.securevault.file.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;

import java.time.Instant;
import java.util.List;

/** Wire shapes for the file/search API. Every payload field is ciphertext or a blind index. */
public final class FileDtos {

    private FileDtos() {
    }

    public record TagPayload(
            @NotEmpty List<@NotBlank String> grams,
            @NotBlank String tagCipher,
            @NotBlank String tagIv) {
    }

    /**
     * A new upload. The bytes/meta/tags are now encrypted under a random per-file
     * data key (DEK), and the owner's envelope wraps that DEK under their encKey
     * ({@code encryptedDek} + {@code dekIv}). The server still sees only ciphertext.
     */
    public record UploadRequest(
            @NotBlank String metaCipher,
            @NotBlank String metaIv,
            @NotBlank String blobCipher,
            @NotBlank String blobIv,
            @NotBlank String encryptedDek,
            @NotBlank String dekIv,
            List<TagPayload> tags) {
    }

    public record TagView(String tagCipher, String tagIv) {
    }

    /**
     * The viewer's wrapped data key for a file. {@code wrapType} tells the client
     * how to open it: {@code SYMMETRIC} → AES-GCM-unwrap under encKey (uses
     * {@code dekIv}); {@code OPENPGP} → decrypt the armored message with the
     * OpenPGP private key ({@code dekIv} is null).
     */
    public record Envelope(String encryptedDek, String dekIv, String wrapType) {
    }

    /**
     * File summary returned for listing/search — no file bytes. Carries the
     * viewer's envelope plus who owns it and the viewer's role, so the client can
     * unwrap the DEK and decrypt the metadata + tags. Shared files (role READER)
     * appear here too.
     */
    public record FileView(
            Long id,
            String ownerUsername,
            String role,
            String metaCipher,
            String metaIv,
            Instant createdAt,
            Envelope envelope,
            List<TagView> tags) {
    }

    /** Full encrypted file content for download, including the viewer's envelope. */
    public record FileContent(
            Long id,
            String ownerUsername,
            String metaCipher,
            String metaIv,
            String blobCipher,
            String blobIv,
            Envelope envelope) {
    }

    /** Trigram blind indexes for every search term, de-duplicated, ANDed at the file level. */
    public record SearchRequest(@NotEmpty List<@NotBlank String> grams) {
    }

    /**
     * Share a file with another user. The client has already unwrapped the file's
     * DEK and re-encrypted it to the recipient's OpenPGP public key, so
     * {@code encryptedDek} is an ASCII-armored OpenPGP message.
     */
    public record ShareRequest(
            @NotBlank String recipientUsername,
            @NotBlank String encryptedDek) {
    }

    /** One recipient a file is shared with (for the owner's "shared with" list). */
    public record ShareView(String recipientUsername, Instant createdAt) {
    }

    /** A user's OpenPGP public key, fetched before wrapping a DEK to them. */
    public record PublicKeyResponse(String username, String publicKey) {
    }
}
