package com.example.securevault.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;

import java.time.Instant;

/**
 * A vault owner. The server stores only public key-derivation parameters
 * (salt + iteration count) and a login {@code verifier}. It never sees the
 * password, the derived keys, or any plaintext — all crypto happens in the
 * browser (zero-knowledge model).
 */
@Entity
@Table(name = "vault_user")
public class VaultUser {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String username;

    /** Random per-user PBKDF2 salt, base64. Public — salts are not secret. */
    @Column(nullable = false)
    private String kdfSalt;

    /** PBKDF2 iteration count the client used, stored so it can reproduce keys. */
    @Column(nullable = false)
    private int kdfIterations;

    /**
     * Login verifier, base64. A value the client derives from the password
     * (a key separate from the encryption/index keys). Proves password
     * knowledge without revealing the password or the encryption keys.
     */
    @Column(nullable = false)
    private String verifier;

    /**
     * The user's OpenPGP public key (ASCII-armored). Public by definition — it
     * is handed to other users so they can wrap a file's data key to it when
     * sharing. Authenticity is the client's responsibility (fingerprint / TOFU).
     */
    @Lob
    @Column(nullable = false)
    private String publicKey;

    /**
     * The user's OpenPGP private key (ASCII-armored), itself AES-GCM-encrypted
     * under the password-derived {@code encKey} before it ever leaves the
     * browser. The server stores only this ciphertext blob + its IV and can
     * never read the private key — same zero-knowledge posture as everything else.
     */
    @Lob
    @Column(nullable = false)
    private String wrappedPrivateKey;

    /** AES-GCM IV for {@link #wrappedPrivateKey}, base64. */
    @Column(nullable = false)
    private String wrappedPrivateKeyIv;

    @Column(nullable = false)
    private Instant createdAt = Instant.now();

    protected VaultUser() {
    }

    public VaultUser(String username, String kdfSalt, int kdfIterations, String verifier,
                     String publicKey, String wrappedPrivateKey, String wrappedPrivateKeyIv) {
        this.username = username;
        this.kdfSalt = kdfSalt;
        this.kdfIterations = kdfIterations;
        this.verifier = verifier;
        this.publicKey = publicKey;
        this.wrappedPrivateKey = wrappedPrivateKey;
        this.wrappedPrivateKeyIv = wrappedPrivateKeyIv;
    }

    public Long getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public String getKdfSalt() {
        return kdfSalt;
    }

    public int getKdfIterations() {
        return kdfIterations;
    }

    public String getVerifier() {
        return verifier;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public String getWrappedPrivateKey() {
        return wrappedPrivateKey;
    }

    public String getWrappedPrivateKeyIv() {
        return wrappedPrivateKeyIv;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
