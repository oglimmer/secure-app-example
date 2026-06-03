package com.example.securevault.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Lob;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

import java.time.Instant;

/**
 * An uploaded file. Both the file bytes and the metadata (filename,
 * content-type, size) are stored as AES-GCM ciphertext produced in the
 * browser. The server cannot read either without the user's password.
 */
@Entity
@Table(name = "file_entry", indexes = {
        @Index(name = "idx_file_owner", columnList = "owner_id")
})
public class FileEntry {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "owner_id", nullable = false)
    private VaultUser owner;

    /** Encrypted JSON {filename, contentType, size}, base64. */
    @Column(nullable = false, length = 8192)
    private String metaCipher;

    /** AES-GCM IV for the metadata, base64. */
    @Column(nullable = false)
    private String metaIv;

    /** Encrypted file bytes, base64. */
    @Lob
    @Column(nullable = false)
    private String blobCipher;

    /** AES-GCM IV for the file bytes, base64. */
    @Column(nullable = false)
    private String blobIv;

    @Column(nullable = false)
    private Instant createdAt = Instant.now();

    protected FileEntry() {
    }

    public FileEntry(VaultUser owner, String metaCipher, String metaIv, String blobCipher, String blobIv) {
        this.owner = owner;
        this.metaCipher = metaCipher;
        this.metaIv = metaIv;
        this.blobCipher = blobCipher;
        this.blobIv = blobIv;
    }

    public Long getId() {
        return id;
    }

    public VaultUser getOwner() {
        return owner;
    }

    public String getMetaCipher() {
        return metaCipher;
    }

    public String getMetaIv() {
        return metaIv;
    }

    public String getBlobCipher() {
        return blobCipher;
    }

    public String getBlobIv() {
        return blobIv;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
