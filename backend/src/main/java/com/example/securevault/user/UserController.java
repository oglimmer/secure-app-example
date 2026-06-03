package com.example.securevault.user;

import com.example.securevault.domain.VaultUser;
import com.example.securevault.file.dto.FileDtos.PublicKeyResponse;
import com.example.securevault.repo.VaultUserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Directory lookup for sharing: returns a user's OpenPGP public key so another
 * user can wrap a file's data key to it.
 *
 * <p>SECURITY NOTE: the server is untrusted, so it could serve an attacker's
 * public key in place of the real recipient's — then a share would be encrypted
 * to the attacker. Defending against this needs out-of-band key verification
 * (the client shows the fingerprint to confirm, TOFU-pins it on first use). As a
 * prototype we surface the fingerprint and accept "the server can misdirect a
 * <em>new</em> share" as a documented residual risk — the same trust posture as
 * the existing username-enumeration on {@code /auth/params}.
 */
@RestController
@RequestMapping("/api/users")
public class UserController {

    private final VaultUserRepository users;

    public UserController(VaultUserRepository users) {
        this.users = users;
    }

    @GetMapping("/{username}/pubkey")
    public PublicKeyResponse pubkey(@PathVariable String username) {
        VaultUser user = users.findByUsername(username)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "unknown user"));
        return new PublicKeyResponse(user.getUsername(), user.getPublicKey());
    }
}
