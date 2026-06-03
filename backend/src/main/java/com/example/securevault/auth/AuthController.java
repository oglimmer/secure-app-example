package com.example.securevault.auth;

import com.example.securevault.domain.VaultUser;
import com.example.securevault.repo.VaultUserRepository;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final VaultUserRepository users;
    private final SessionService sessions;

    public AuthController(VaultUserRepository users, SessionService sessions) {
        this.users = users;
        this.sessions = sessions;
    }

    public record RegisterRequest(
            @NotBlank String username,
            @NotBlank String salt,
            @Min(1) int iterations,
            @NotBlank String verifier,
            // The client's OpenPGP identity, generated at registration. publicKey
            // is cleartext; privateKey arrives already AES-GCM-encrypted under encKey.
            @NotBlank String publicKey,
            @NotBlank String wrappedPrivateKey,
            @NotBlank String wrappedPrivateKeyIv) {
    }

    public record AuthParamsResponse(String salt, int iterations) {
    }

    public record LoginRequest(@NotBlank String username, @NotBlank String verifier) {
    }

    /**
     * On login the client also needs its OpenPGP identity back: the public key
     * and the encKey-wrapped private key (which only the client can decrypt) so
     * it can read files shared to it and sign new shares.
     */
    public record LoginResponse(String token, Long userId, String publicKey,
                                String wrappedPrivateKey, String wrappedPrivateKeyIv) {
    }

    /**
     * Create a vault. The body carries only public KDF params, the login
     * verifier, and the OpenPGP identity (public key + encKey-wrapped private key).
     */
    @PostMapping("/register")
    public ResponseEntity<Void> register(@Valid @RequestBody RegisterRequest req) {
        if (users.existsByUsername(req.username())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "username already taken");
        }
        users.save(new VaultUser(req.username(), req.salt(), req.iterations(), hashVerifier(req.verifier()),
                req.publicKey(), req.wrappedPrivateKey(), req.wrappedPrivateKeyIv()));
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    /**
     * Public key-derivation parameters for a username. The client needs these
     * before it can derive keys to log in. (For a prototype we accept the
     * username-enumeration this enables.)
     */
    @GetMapping("/params")
    public AuthParamsResponse params(@RequestParam String username) {
        VaultUser user = users.findByUsername(username)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "unknown user"));
        return new AuthParamsResponse(user.getKdfSalt(), user.getKdfIterations());
    }

    /** Exchange a password-derived verifier for a session token. */
    @PostMapping("/login")
    public LoginResponse login(@Valid @RequestBody LoginRequest req) {
        VaultUser user = users.findByUsername(req.username())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid credentials"));

        // Compare hashes, not the verifier itself: the DB only ever holds the
        // hash. Constant-time to avoid leaking the prefix match via timing.
        boolean ok = MessageDigest.isEqual(
                user.getVerifierHash().getBytes(StandardCharsets.UTF_8),
                hashVerifier(req.verifier()).getBytes(StandardCharsets.UTF_8));
        if (!ok) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid credentials");
        }
        return new LoginResponse(sessions.issueToken(user.getId()), user.getId(),
                user.getPublicKey(), user.getWrappedPrivateKey(), user.getWrappedPrivateKeyIv());
    }

    /**
     * base64(SHA-256(verifier)). The verifier is a 256-bit password-derived key,
     * so a single SHA-256 makes the stored value irreversible and non-replayable
     * without the cost of a slow password hash (the entropy is already there).
     */
    private static String hashVerifier(String verifier) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(verifier.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e); // never on a standard JRE
        }
    }
}
