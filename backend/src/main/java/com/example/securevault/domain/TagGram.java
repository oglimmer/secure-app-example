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
 * One trigram blind index for one tag's text: base64(HMAC-SHA256(indexKey,
 * trigram)), computed in the browser. A tag is split into all of its length-3
 * substrings and each is stored as a separate row, so the server can answer
 * "contains Q" by checking that a file holds <em>all</em> of Q's trigrams — an
 * indexed lookup that never sees the tag text or the index key.
 *
 * <p>This is what makes server-side substring search possible. The trade-off is
 * extra leakage: the server can observe per-file trigram multisets and attempt
 * frequency / co-occurrence analysis to guess tag contents. The encrypted tag
 * text itself lives once on {@link TagEntry}.
 */
@Entity
@Table(name = "tag_gram", indexes = {
        // Every search is "owner = ? AND blindIndex IN (query trigrams)".
        @Index(name = "idx_gram_owner_blind", columnList = "owner_id, blindIndex"),
        @Index(name = "idx_gram_file", columnList = "file_id")
})
public class TagGram {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "owner_id", nullable = false)
    private VaultUser owner;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "file_id", nullable = false)
    private FileEntry file;

    /** HMAC-SHA256(indexKey, one trigram of normalize(tag)), base64. Searchable. */
    @Column(nullable = false, length = 64)
    private String blindIndex;

    protected TagGram() {
    }

    public TagGram(VaultUser owner, FileEntry file, String blindIndex) {
        this.owner = owner;
        this.file = file;
        this.blindIndex = blindIndex;
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

    public String getBlindIndex() {
        return blindIndex;
    }
}
