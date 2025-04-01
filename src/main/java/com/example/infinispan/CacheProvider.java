package com.example.infinispan;

import com.example.session.UserSession;
import com.nimbusds.jose.jwk.ECKey;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Inject;
import org.infinispan.Cache;
import org.infinispan.manager.EmbeddedCacheManager;

/**
 * Provides cache instances for the application
 */
@ApplicationScoped
public class CacheProvider {

    // Use the quarkus.infinispan-embedded.xml-config property to set the path to an XML file that includes the configuration of the injected instance.
    @Inject
    EmbeddedCacheManager cacheManager;

    /**
     * Produces the session cache
     *
     * @return Cache for user sessions
     */
    @Produces
    @ApplicationScoped
    public Cache<String, UserSession> sessionCache() {
        return cacheManager.getCache("sessions");
    }

    /**
     * Produces the JWT keys cache
     *
     * @return Cache for JWT keys
     */
    @Produces
    @ApplicationScoped
    public Cache<String, ECKey> jwtKeyCache() {
        return cacheManager.getCache("jwt-keys");
    }
}