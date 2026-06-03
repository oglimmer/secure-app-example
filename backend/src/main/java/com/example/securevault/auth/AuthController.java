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
            @NotBlank String verifier) {
    }

    public record AuthParamsResponse(String salt, int iterations) {
    }

    public record LoginRequest(@NotBlank String username, @NotBlank String verifier) {
    }

    public record LoginResponse(String token, Long userId) {
    }

    /** Create a vault. The body carries only public KDF params + the login verifier. */
    @PostMapping("/register")
    public ResponseEntity<Void> register(@Valid @RequestBody RegisterRequest req) {
        if (users.existsByUsername(req.username())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "username already taken");
        }
        users.save(new VaultUser(req.username(), req.salt(), req.iterations(), req.verifier()));
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

        boolean ok = MessageDigest.isEqual(
                user.getVerifier().getBytes(StandardCharsets.UTF_8),
                req.verifier().getBytes(StandardCharsets.UTF_8));
        if (!ok) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid credentials");
        }
        return new LoginResponse(sessions.issueToken(user.getId()), user.getId());
    }
}
