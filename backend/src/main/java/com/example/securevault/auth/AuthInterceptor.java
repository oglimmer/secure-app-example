package com.example.securevault.auth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * Resolves the {@code Authorization: Bearer <token>} header to a user id and
 * stashes it as the {@code userId} request attribute for guarded endpoints.
 * Rejects with 401 when the token is missing or unknown.
 */
@Component
public class AuthInterceptor implements HandlerInterceptor {

    public static final String USER_ID_ATTRIBUTE = "userId";

    private final SessionService sessions;

    public AuthInterceptor(SessionService sessions) {
        this.sessions = sessions;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        String header = request.getHeader("Authorization");
        String token = (header != null && header.startsWith("Bearer "))
                ? header.substring("Bearer ".length())
                : null;

        var userId = sessions.resolveUserId(token);
        if (userId.isEmpty()) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return false;
        }
        request.setAttribute(USER_ID_ATTRIBUTE, userId.get());
        return true;
    }
}
