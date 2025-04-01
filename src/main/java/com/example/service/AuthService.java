package com.example.service;

import com.example.jwt.JwtManager;
import com.example.session.SessionManager;
import com.example.session.UserSession;
import io.quarkus.oidc.IdToken;
import io.quarkus.oidc.OidcSession;
import io.quarkus.oidc.RefreshToken;
import io.quarkus.oidc.TokenIntrospection;
import io.quarkus.oidc.UserInfo;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.Cookie;
import jakarta.ws.rs.core.NewCookie;
import jakarta.ws.rs.core.UriInfo;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;

/**
 * Service handling authentication and token management
 */
@ApplicationScoped
public class AuthService {
    private static final Logger LOG = LoggerFactory.getLogger(AuthService.class);

    @Inject
    SessionManager sessionManager;

    @Inject
    JwtManager jwtManager;

    @Inject
    SecurityIdentity identity;

    @Inject
    @IdToken
    JsonWebToken idToken;

    @Inject
    RefreshToken refreshToken;

    @Inject
    OidcSession oidcSession;

    @Inject
    UserInfo userInfo;

    /**
     * Handles authentication success and creates/updates user session
     *
     * @param cookie Existing session cookie if available
     * @param uriInfo The URI info from the request
     * @param idpName The identity provider name
     * @return Authentication result with cookies and tokens
     */
    public AuthResult handleAuthentication(Cookie cookie, UriInfo uriInfo, String idpName) {
        UserSession session = getOrCreateSession(cookie, uriInfo);

        // Store tokens in the session
        updateSessionWithTokens(session, idpName);

        // Generate internal JWT
        String internalJwt = jwtManager.createInternalJwt(session);

        // Update the session
        sessionManager.updateSession(session);

        // Create a new cookie if needed
        NewCookie newCookie = cookie == null ?
                sessionManager.createSession(uriInfo) : null;

        return new AuthResult(internalJwt, newCookie, session.getUserId());
    }

    /**
     * Logs out a user by invalidating their session
     *
     * @param cookie The session cookie
     * @param uriInfo The URI info from the request
     * @return A cookie that invalidates the session in the browser
     */
    public NewCookie logout(Cookie cookie, UriInfo uriInfo) {
        if (cookie == null) {
            return null;
        }

        // Get the session and then invalidate it
        Optional<UserSession> sessionOpt = sessionManager.getSession(cookie);

        // Try to logout from the OIDC provider
        if (sessionOpt.isPresent() && oidcSession != null) {
            try {
                oidcSession.logout();
            } catch (Exception e) {
                LOG.warn("Failed to logout from OIDC provider", e);
            }
        }

        return sessionManager.invalidateSession(cookie.getValue(), uriInfo);
    }

    /**
     * Validates a session and optionally refreshes the token if needed
     *
     * @param cookie The session cookie
     * @param uriInfo The URI info from the request
     * @return The validation result
     */
    public ValidationResult validateSession(Cookie cookie, UriInfo uriInfo) {
        if (cookie == null) {
            return ValidationResult.invalid();
        }

        Optional<UserSession> sessionOpt = sessionManager.getSession(cookie);
        if (sessionOpt.isEmpty()) {
            return ValidationResult.invalid();
        }

        UserSession session = sessionOpt.get();

        // Check if the token is expired and needs to be refreshed
        if (session.isTokenExpired() && session.getRefreshToken() != null) {
            try {
                // Attempt to refresh the token
                if (refreshToken.refreshToken(session.getRefreshToken())) {
                    updateSessionWithTokens(session, session.getIdpName());
                    sessionManager.updateSession(session);
                } else {
                    // If refresh fails, invalidate the session
                    NewCookie invalidationCookie = sessionManager.invalidateSession(session.getSessionId(), uriInfo);
                    return ValidationResult.expired(invalidationCookie);
                }
            } catch (Exception e) {
                LOG.error("Error refreshing token", e);
                NewCookie invalidationCookie = sessionManager.invalidateSession(session.getSessionId(), uriInfo);
                return ValidationResult.expired(invalidationCookie);
            }
        }

        // Generate a new internal JWT
        String internalJwt = jwtManager.createInternalJwt(session);

        return ValidationResult.valid(internalJwt, session.getUserId());
    }

    private UserSession getOrCreateSession(Cookie cookie, UriInfo uriInfo) {
        if (cookie != null) {
            Optional<UserSession> existingSession = sessionManager.getSession(cookie);
            if (existingSession.isPresent()) {
                return existingSession.get();
            }
        }

        // Create a new session
        NewCookie newCookie = sessionManager.createSession(uriInfo);
        return sessionManager.getSession(newCookie.toCookie()).orElseThrow();
    }

    private void updateSessionWithTokens(UserSession session, String idpName) {
        // Extract user ID and username
        String userId = identity.getPrincipal().getName();
        String username = identity.getAttribute("preferred_username");

        // Get the access token
        String accessToken = identity.getAttribute("access_token");

        // Get token expiration
        Long expiresAt = identity.getAttribute("exp");
        Instant expiration = expiresAt != null ?
                Instant.ofEpochSecond(expiresAt) :
                Instant.now().plusSeconds(3600);

        // Get the ID token
        String idTokenStr = idToken != null ? idToken.getRawToken() : null;

        // Get the refresh token
        String refreshTokenStr = refreshToken != null ? refreshToken.getToken() : null;

        // Update session
        session.setUserId(userId);
        session.setUsername(username);
        session.setOauthToken(accessToken);
        session.setRefreshToken(refreshTokenStr);
        session.setTokenExpiration(expiration);
        session.setIdToken(idTokenStr);
        session.setIdpName(idpName);

        // Add user claims as session attributes
        if (identity.getAttributes() != null) {
            for (Map.Entry<String, Object> entry : identity.getAttributes().entrySet()) {
                // Store claims with a prefix to avoid collisions
                session.setAttribute("claim." + entry.getKey(), entry.getValue());
            }
        }

        // Add userinfo if available
        if (userInfo != null) {
            try {
                Map<String, Object> userInfoMap = userInfo.getUserInfo();
                if (userInfoMap != null) {
                    for (Map.Entry<String, Object> entry : userInfoMap.entrySet()) {
                        session.setAttribute("userinfo." + entry.getKey(), entry.getValue());
                    }
                }
            } catch (Exception e) {
                LOG.warn("Failed to get userinfo", e);
            }
        }
    }

    public static class AuthResult {
        private final String token;
        private final NewCookie cookie;
        private final String userId;

        public AuthResult(String token, NewCookie cookie, String userId) {
            this.token = token;
            this.cookie = cookie;
            this.userId = userId;
        }

        public String getToken() {
            return token;
        }

        public NewCookie getCookie() {
            return cookie;
        }

        public String getUserId() {
            return userId;
        }
    }

    public static class ValidationResult {
        private final boolean valid;
        private final boolean expired;
        private final String token;
        private final NewCookie invalidationCookie;
        private final String userId;

        private ValidationResult(boolean valid, boolean expired, String token, NewCookie invalidationCookie, String userId) {
            this.valid = valid;
            this.expired = expired;
            this.token = token;
            this.invalidationCookie = invalidationCookie;
            this.userId = userId;
        }

        public static ValidationResult valid(String token, String userId) {
            return new ValidationResult(true, false, token, null, userId);
        }

        public static ValidationResult invalid() {
            return new ValidationResult(false, false, null, null, null);
        }

        public static ValidationResult expired(NewCookie invalidationCookie) {
            return new ValidationResult(false, true, null, invalidationCookie, null);
        }

        public boolean isValid() {
            return valid;
        }

        public boolean isExpired() {
            return expired;
        }

        public String getToken() {
            return token;
        }

        public NewCookie getInvalidationCookie() {
            return invalidationCookie;
        }

        public String getUserId() {
            return userId;
        }
    }
}