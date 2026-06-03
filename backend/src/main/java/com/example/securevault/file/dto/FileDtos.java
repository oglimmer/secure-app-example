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

    public record UploadRequest(
            @NotBlank String metaCipher,
            @NotBlank String metaIv,
            @NotBlank String blobCipher,
            @NotBlank String blobIv,
            List<TagPayload> tags) {
    }

    public record TagView(String tagCipher, String tagIv) {
    }

    /** File summary returned for listing/search — no file bytes, only encrypted metadata + tags. */
    public record FileView(
            Long id,
            String metaCipher,
            String metaIv,
            Instant createdAt,
            List<TagView> tags) {
    }

    /** Full encrypted file content for download. */
    public record FileContent(
            Long id,
            String metaCipher,
            String metaIv,
            String blobCipher,
            String blobIv) {
    }

    /** Trigram blind indexes for every search term, de-duplicated, ANDed at the file level. */
    public record SearchRequest(@NotEmpty List<@NotBlank String> grams) {
    }
}
