package com.example.session;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.Cookie;
import jakarta.ws.rs.core.NewCookie;
import jakarta.ws.rs.core.UriInfo;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.infinispan.Cache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;

@ApplicationScoped
public class SessionManager {
    private static final Logger LOG = LoggerFactory.getLogger(SessionManager.class);
    private static final String SESSION_COOKIE_NAME = "AUTH_SESSION";
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    @Inject
    Cache<String, UserSession> sessionCache;

    @ConfigProperty(name = "quarkus.http.cookie.same-site", defaultValue = "lax")
    String sameSite;

    @ConfigProperty(name = "session.expiration", defaultValue = "3600")
    long sessionExpirationSeconds;

    @ConfigProperty(name = "session.cookie.domain")
    Optional<String> cookieDomain;

    @ConfigProperty(name = "session.cookie.path", defaultValue = "/")
    String cookiePath;

    @ConfigProperty(name = "session.cookie.secure", defaultValue = "true")
    boolean cookieSecure;

    @ConfigProperty(name = "session.cookie.http-only", defaultValue = "true")
    boolean cookieHttpOnly;

    /**
     * Creates a new session and generates a session cookie
     *
     * @param uriInfo The URI info from the request
     * @return A new cookie for the created session
     */
    public NewCookie createSession(UriInfo uriInfo) {
        String sessionId = generateSessionId();
        UserSession session = new UserSession(sessionId);
        sessionCache.put(sessionId, session);

        LOG.debug("Created new session: {}", sessionId);

        return createSessionCookie(sessionId, uriInfo);
    }

    /**
     * Retrieves a session based on the cookie value
     *
     * @param cookie The session cookie
     * @return The user session if found
     */
    public Optional<UserSession> getSession(Cookie cookie) {
        if (cookie == null) {
            return Optional.empty();
        }

        String sessionId = cookie.getValue();
        UserSession session = sessionCache.get(sessionId);

        if (session == null) {
            LOG.debug("Session not found or expired: {}", sessionId);
            return Optional.empty();
        }

        // Update last accessed time
        session.updateLastAccessed();
        sessionCache.put(sessionId, session);
        sessionCache.

        return Optional.of(session);
    }

    /**
     * Updates a session with new data
     *
     * @param session The session to update
     */
    public void updateSession(UserSession session) {
        session.updateLastAccessed();
        sessionCache.put(session.getSessionId(), session);
    }

    /**
     * Invalidates a session
     *
     * @param sessionId The session ID to invalidate
     * @return A cookie that invalidates the session in the browser
     */
    public NewCookie invalidateSession(String sessionId, UriInfo uriInfo) {
        if (sessionId != null) {
            sessionCache.remove(sessionId);
            LOG.debug("Invalidated session: {}", sessionId);
        }

        return createSessionInvalidationCookie(uriInfo);
    }

    private String generateSessionId() {
        byte[] randomBytes = new byte[32];
        SECURE_RANDOM.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    private NewCookie createSessionCookie(String sessionId, UriInfo uriInfo) {
        return new NewCookie.Builder(SESSION_COOKIE_NAME)
                .value(sessionId)
                .path(cookiePath)
                .domain(cookieDomain.orElse(null))
                .maxAge((int) sessionExpirationSeconds)
                .secure(cookieSecure || uriInfo.getRequestUri().getScheme().equals("https"))
                .httpOnly(cookieHttpOnly)
                .sameSite(NewCookie.SameSite.valueOf(sameSite.toUpperCase()))
                .build();
    }

    private NewCookie createSessionInvalidationCookie(UriInfo uriInfo) {
        return new NewCookie.Builder(SESSION_COOKIE_NAME)
                .value("")
                .path(cookiePath)
                .domain(cookieDomain.orElse(null))
                .maxAge(0)
                .secure(cookieSecure || uriInfo.getRequestUri().getScheme().equals("https"))
                .httpOnly(cookieHttpOnly)
                .sameSite(NewCookie.SameSite.valueOf(sameSite.toUpperCase()))
                .build();
    }
}