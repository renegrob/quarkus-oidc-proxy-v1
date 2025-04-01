package com.example.jwt;

import com.example.session.UserSession;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.smallrye.jwt.build.Jwt;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.infinispan.Cache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.interfaces.ECPrivateKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

@ApplicationScoped
public class JwtManager {
    private static final Logger LOG = LoggerFactory.getLogger(JwtManager.class);
    private static final String JWT_KEY_CACHE_ID = "es384-key";

    @Inject
    Cache<String, ECKey> jwtKeyCache;

    @ConfigProperty(name = "quarkus.jwt.signing-key-location", defaultValue = "")
    String signingKeyLocation;

    @ConfigProperty(name = "quarkus.jwt.internal-token-expiration", defaultValue = "3600")
    long tokenExpirationSeconds;

    @ConfigProperty(name = "quarkus.jwt.internal-token-issuer", defaultValue = "oauth-delegate")
    String tokenIssuer;

    @ConfigProperty(name = "quarkus.jwt.internal-token-audience", defaultValue = "backend-services")
    String tokenAudience;

    private ECKey signingKey;
    private ECPrivateKey privateKey;

    @PostConstruct
    public void initialize() {
        // Try to load the key from the specified location if provided
        if (!signingKeyLocation.isEmpty()) {
            try {
                String keyContent = Files.readString(Paths.get(signingKeyLocation));
                signingKey = ECKey.parse(keyContent);
                privateKey = signingKey.toECPrivateKey();
                LOG.info("Loaded JWT signing key from location: {}", signingKeyLocation);

                // Store the key in the cache
                jwtKeyCache.put(JWT_KEY_CACHE_ID, signingKey);
                return;
            } catch (Exception e) {
                LOG.warn("Failed to load JWT signing key from location: {}. Will generate a new key.", signingKeyLocation, e);
            }
        }

        // Try to load from the cache
        signingKey = jwtKeyCache.get(JWT_KEY_CACHE_ID);

        if (signingKey == null) {
            // Generate a new key if none found
            try {
                signingKey = new ECKeyGenerator(Curve.P_384)
                        .keyID(UUID.randomUUID().toString())
                        .generate();

                privateKey = signingKey.toECPrivateKey();

                // Store the key in the cache
                jwtKeyCache.put(JWT_KEY_CACHE_ID, signingKey);
                LOG.info("Generated new ES384 JWT signing key");

                // Optionally save the key to the file system if location is provided
                if (!signingKeyLocation.isEmpty()) {
                    try {
                        Files.writeString(Path.of(signingKeyLocation), signingKey.toJSONString());
                        LOG.info("Saved JWT signing key to location: {}", signingKeyLocation);
                    } catch (IOException e) {
                        LOG.warn("Failed to save JWT signing key to location: {}", signingKeyLocation, e);
                    }
                }
            } catch (JOSEException e) {
                LOG.error("Failed to generate JWT signing key", e);
                throw new RuntimeException("Failed to initialize JWT signing capabilities", e);
            }
        } else {
            try {
                privateKey = signingKey.toECPrivateKey();
                LOG.info("Loaded JWT signing key from cache");
            } catch (JOSEException e) {
                LOG.error("Failed to parse JWT signing key from cache", e);
                throw new RuntimeException("Failed to initialize JWT signing capabilities", e);
            }
        }
    }

    /**
     * Creates an internal JWT token based on user session information
     *
     * @param session The user session
     * @return A signed JWT token
     */
    public String createInternalJwt(UserSession session) {
        try {
            JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                    .subject(session.getUserId())
                    .issuer(tokenIssuer)
                    .audience(tokenAudience)
                    .jwtID(UUID.randomUUID().toString())
                    .issueTime(new Date())
                    .expirationTime(Date.from(Instant.now().plus(Duration.ofSeconds(tokenExpirationSeconds))));

            // Add username if available
            if (session.getUsername() != null) {
                claimsBuilder.claim("preferred_username", session.getUsername());
            }

            // Add IDP information
            if (session.getIdpName() != null) {
                claimsBuilder.claim("idp", session.getIdpName());
            }

            // Add any additional custom claims from session attributes
            for (String key : session.getAttributes().keySet()) {
                if (key.startsWith("claim.")) {
                    String claimName = key.substring(6); // Remove "claim." prefix
                    claimsBuilder.claim(claimName, session.getAttribute(key));
                }
            }

            // Create the JWT with the ES384 algorithm
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES384)
                    .keyID(signingKey.getKeyID())
                    .build();

            SignedJWT signedJWT = new SignedJWT(header, claimsBuilder.build());

            // Sign the JWT
            ECDSASigner signer = new ECDSASigner(privateKey);
            signedJWT.sign(signer);

            return signedJWT.serialize();
        } catch (JOSEException e) {
            LOG.error("Failed to sign JWT", e);
            throw new RuntimeException("Failed to create internal JWT token", e);
        }
    }

    /**
     * Gets the public JWK that can be used to verify tokens
     *
     * @return The public JWK in JSON format
     */
    public String getPublicJwk() {
        try {
            // Create a copy with only the public components
            ECKey publicKey = signingKey.toPublicJWK();
            return publicKey.toJSONString();
        } catch (Exception e) {
            LOG.error("Failed to get public JWK", e);
            throw new RuntimeException("Failed to get public JWK", e);
        }
    }
}