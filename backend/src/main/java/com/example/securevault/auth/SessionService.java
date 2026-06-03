package com.example.securevault.auth;

import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Minimal in-memory bearer-token session store (prototype). A successful login
 * mints an opaque token mapped to a user id. There is no persistence and no
 * expiry — tokens live for the lifetime of the process. Swap for JWT/Redis in
 * production.
 */
@Service
public class SessionService {

    private final ConcurrentMap<String, Long> tokenToUserId = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();

    public String issueToken(Long userId) {
        byte[] raw = new byte[32];
        random.nextBytes(raw);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        tokenToUserId.put(token, userId);
        return token;
    }

    public Optional<Long> resolveUserId(String token) {
        if (token == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(tokenToUserId.get(token));
    }

    public void invalidate(String token) {
        if (token != null) {
            tokenToUserId.remove(token);
        }
    }
}
