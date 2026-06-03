package com.example.securevault.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

/**
 * One tag attached to one file. Holds the AES-GCM-encrypted tag text once;
 * {@code tagCipher} is returned to the client so it can display (and verify) the
 * real tag after decrypting locally.
 *
 * <p>The searchable tokens are NOT here — they live in {@link TagGram}, one row
 * per trigram of the tag, which is what enables server-side "contains" search.
 */
@Entity
@Table(name = "tag_entry", indexes = {
        @Index(name = "idx_tag_file", columnList = "file_id")
})
public class TagEntry {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "owner_id", nullable = false)
    private VaultUser owner;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "file_id", nullable = false)
    private FileEntry file;

    /** AES-GCM-encrypted tag text, base64. */
    @Column(nullable = false, length = 1024)
    private String tagCipher;

    /** AES-GCM IV for the tag text, base64. */
    @Column(nullable = false)
    private String tagIv;

    protected TagEntry() {
    }

    public TagEntry(VaultUser owner, FileEntry file, String tagCipher, String tagIv) {
        this.owner = owner;
        this.file = file;
        this.tagCipher = tagCipher;
        this.tagIv = tagIv;
    }

    public Long getId() {
        return id;
    }

    public VaultUser getOwner() {
        return owner;
    }

    public FileEntry getFile() {
        return file;
    }

    public String getTagCipher() {
        return tagCipher;
    }

    public String getTagIv() {
        return tagIv;
    }
}
