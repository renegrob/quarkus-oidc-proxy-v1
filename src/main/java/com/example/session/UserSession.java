package com.example.session;

import java.io.Serializable;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * Represents a user session that can be stored in the Infinispan cache
 */
public class UserSession implements Serializable {
    private static final long serialVersionUID = 1L;

    private final String sessionId;
    private String userId;
    private String username;
    private String oauthToken;
    private String refreshToken;
    private Instant tokenExpiration;
    private String idToken;
    private String idpName;
    private final Instant creationTime;
    private Instant lastAccessedTime;
    private Map<String, Object> attributes;

    public UserSession(String sessionId) {
        this.sessionId = sessionId;
        this.creationTime = Instant.now();
        this.lastAccessedTime = Instant.now();
        this.attributes = new HashMap<>();
    }

    public String getSessionId() {
        return sessionId;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getOauthToken() {
        return oauthToken;
    }

    public void setOauthToken(String oauthToken) {
        this.oauthToken = oauthToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public Instant getTokenExpiration() {
        return tokenExpiration;
    }

    public void setTokenExpiration(Instant tokenExpiration) {
        this.tokenExpiration = tokenExpiration;
    }

    public String getIdToken() {
        return idToken;
    }

    public void setIdToken(String idToken) {
        this.idToken = idToken;
    }

    public String getIdpName() {
        return idpName;
    }

    public void setIdpName(String idpName) {
        this.idpName = idpName;
    }

    public Instant getCreationTime() {
        return creationTime;
    }

    public Instant getLastAccessedTime() {
        return lastAccessedTime;
    }

    public void updateLastAccessed() {
        this.lastAccessedTime = Instant.now();
    }

    public Map<String, Object> getAttributes() {
        return attributes;
    }

    public void setAttribute(String key, Object value) {
        this.attributes.put(key, value);
    }

    public Object getAttribute(String key) {
        return this.attributes.get(key);
    }

    public boolean isTokenExpired() {
        return tokenExpiration != null && Instant.now().isAfter(tokenExpiration);
    }
}