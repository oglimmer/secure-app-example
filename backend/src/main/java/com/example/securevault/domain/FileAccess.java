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
import jakarta.persistence.UniqueConstraint;

import java.time.Instant;

/**
 * One <em>key envelope</em>: it grants {@link #recipient} access to {@link #file}
 * by carrying that file's random per-file data key (DEK), encrypted so that only
 * the recipient can unwrap it.
 *
 * <p>This is the whole basis for sharing. Each file is encrypted once under a
 * random DEK; the bytes are never re-encrypted per recipient. Instead one tiny
 * envelope row per recipient holds the wrapped DEK:
 *
 * <ul>
 *   <li>The <b>owner</b> always gets an envelope with {@code role = OWNER} and
 *       {@code wrapType = SYMMETRIC}: the DEK wrapped under the owner's
 *       password-derived {@code encKey} (AES-GCM). Reading your own files needs
 *       no keypair at all.</li>
 *   <li>A <b>shared</b> recipient gets {@code role = READER} and
 *       {@code wrapType = OPENPGP}: the DEK encrypted to the recipient's OpenPGP
 *       public key. Only their (encKey-wrapped) private key can open it.</li>
 * </ul>
 *
 * <p>The server only ever sees wrapped DEKs — it cannot derive the data key in
 * either case, so the dumb-blob-store property is preserved.
 */
@Entity
@Table(name = "file_access",
        uniqueConstraints = @UniqueConstraint(name = "uq_access_file_recipient",
                columnNames = {"file_id", "recipient_id"}),
        indexes = {
                @Index(name = "idx_access_recipient", columnList = "recipient_id"),
                @Index(name = "idx_access_file", columnList = "file_id")
        })
public class FileAccess {

    public enum Role { OWNER, READER }

    public enum WrapType {
        /** DEK wrapped under the recipient's AES-GCM encKey (the owner's own access). */
        SYMMETRIC,
        /** DEK encrypted to the recipient's OpenPGP public key (a share). */
        OPENPGP
    }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "file_id", nullable = false)
    private FileEntry file;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "recipient_id", nullable = false)
    private VaultUser recipient;

    /**
     * The file's DEK, wrapped for {@link #recipient}. For SYMMETRIC this is
     * base64 AES-GCM ciphertext (with {@link #dekIv}); for OPENPGP it is an
     * ASCII-armored OpenPGP message (and {@link #dekIv} is null).
     */
    @Lob
    @Column(nullable = false)
    private String encryptedDek;

    /** AES-GCM IV for {@link #encryptedDek} when SYMMETRIC, base64; null for OPENPGP. */
    @Column
    private String dekIv;

    @Column(nullable = false, length = 16)
    private String wrapType;

    @Column(nullable = false, length = 16)
    private String role;

    @Column(nullable = false)
    private Instant createdAt = Instant.now();

    protected FileAccess() {
    }

    public FileAccess(FileEntry file, VaultUser recipient, String encryptedDek, String dekIv,
                      WrapType wrapType, Role role) {
        this.file = file;
        this.recipient = recipient;
        this.encryptedDek = encryptedDek;
        this.dekIv = dekIv;
        this.wrapType = wrapType.name();
        this.role = role.name();
    }

    public Long getId() {
        return id;
    }

    public FileEntry getFile() {
        return file;
    }

    public VaultUser getRecipient() {
        return recipient;
    }

    public String getEncryptedDek() {
        return encryptedDek;
    }

    public String getDekIv() {
        return dekIv;
    }

    public String getWrapType() {
        return wrapType;
    }

    public String getRole() {
        return role;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
