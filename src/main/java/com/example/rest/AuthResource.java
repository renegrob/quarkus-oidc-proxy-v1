package com.example.rest;

import com.example.jwt.JwtManager;
import com.example.service.AuthService;
import io.quarkus.security.Authenticated;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * REST endpoints for authentication and token management
 */
@Path("/auth")
@Produces(MediaType.APPLICATION_JSON)
public class AuthResource {
    private static final Logger LOG = LoggerFactory.getLogger(AuthResource.class);
    private static final String SESSION_COOKIE_NAME = "AUTH_SESSION";

    @Inject
    AuthService authService;

    @Inject
    JwtManager jwtManager;

    @Context
    UriInfo uriInfo;

    @ConfigProperty(name = "auth.redirect-uri", defaultValue = "/")
    String defaultRedirectUri;

    /**
     * Validates the session and returns a new internal JWT if valid
     *
     * @param cookie The session cookie
     * @return The validation result
     */
    @GET
    @Path("/validate")
    public Response validateSession(@CookieParam(SESSION_COOKIE_NAME) Cookie cookie) {
        AuthService.ValidationResult result = authService.validateSession(cookie, uriInfo);

        if (!result.isValid()) {
            if (result.isExpired() && result.getInvalidationCookie() != null) {
                return Response.status(Response.Status.UNAUTHORIZED)
                        .cookie(result.getInvalidationCookie())
                        .entity(new ErrorResponse("Session expired", "TOKEN_EXPIRED"))
                        .build();
            }
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity(new ErrorResponse("Invalid session", "INVALID_SESSION"))
                    .build();
        }

        return Response.ok(new TokenResponse(result.getToken(), result.getUserId())).build();
    }

    /**
     * Callback endpoint for OIDC/OAuth2 authentication
     *
     * @param idpName The identity provider name
     * @param cookie The session cookie
     * @param redirect Optional redirect URI
     * @return The authentication result and redirection
     */
    @GET
    @Path("/callback/{idpName}")
    @Authenticated
    public Response callback(
            @PathParam("idpName") String idpName,
            @CookieParam(SESSION_COOKIE_NAME) Cookie cookie,
            @QueryParam("redirect_uri") String redirect) {

        try {
            AuthService.AuthResult result = authService.handleAuthentication(cookie, uriInfo, idpName);

            // Build response with the token
            Response.ResponseBuilder response = Response.ok(new TokenResponse(result.getToken(), result.getUserId()));

            // Add cookie if needed
            if (result.getCookie() != null) {
                response.cookie(result.getCookie());
            }

            // Redirect if requested
            if (redirect != null && !redirect.isEmpty()) {
                response.header("X-Redirect-To", redirect);
            }

            return response.build();
        } catch (Exception e) {
            LOG.error("Authentication error", e);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(new ErrorResponse("Authentication error", "AUTH_ERROR"))
                    .build();
        }
    }

    /**
     * Initiates login for a specific identity provider
     *
     * @param idpName The identity provider name
     * @param redirectUri Optional redirect URI after authentication
     * @return Redirection to the IdP authentication page
     */
    @GET
    @Path("/login/{idpName}")
    public Response login(
            @PathParam("idpName") String idpName,
            @QueryParam("redirect_uri") String redirectUri) {

        // Construct callback URL with redirect if provided
        String callbackUrl = uriInfo.getBaseUriBuilder()
                .path("auth")
                .path("callback")
                .path(idpName)
                .build()
                .toString();

        if (redirectUri != null && !redirectUri.isEmpty()) {
            callbackUrl += "?redirect_uri=" + redirectUri;
        }

        // Redirect to OIDC/OAuth2 provider
        return Response.status(Response.Status.FOUND)
                .header("Location", callbackUrl)
                .build();
    }

    /**
     * Logs out the user
     *
     * @param cookie The session cookie
     * @param redirect Optional redirect URI after logout
     * @return Logout result
     */
    @GET
    @Path("/logout")
    public Response logout(
            @CookieParam(SESSION_COOKIE_NAME) Cookie cookie,
            @QueryParam("redirect_uri") String redirect) {

        NewCookie invalidationCookie = authService.logout(cookie, uriInfo);

        Response.ResponseBuilder response = Response.ok(new LogoutResponse("Logout successful"));

        if (invalidationCookie != null) {
            response.cookie(invalidationCookie);
        }

        // Redirect if requested
        if (redirect != null && !redirect.isEmpty()) {
            response.header("X-Redirect-To", redirect);
        } else if (defaultRedirectUri != null && !defaultRedirectUri.isEmpty()) {
            response.header("X-Redirect-To", defaultRedirectUri);
        }

        return response.build();
    }

    /**
     * Returns the public JWK that can be used to verify internal tokens
     *
     * @return The public JWK
     */
    @GET
    @Path("/jwks")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getJwks() {
        try {
            String jwk = jwtManager.getPublicJwk();
            // Format as a JWK Set
            String jwkSet = "{\"keys\":[" + jwk + "]}";
            return Response.ok(jwkSet).build();
        } catch (Exception e) {
            LOG.error("Failed to get JWKs", e);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(new ErrorResponse("Failed to get JWKs", "JWKS_ERROR"))
                    .build();
        }
    }

    // Response classes
    public static class TokenResponse {
        private final String token;
        private final String userId;

        public TokenResponse(String token, String userId) {
            this.token = token;
            this.userId = userId;
        }

        public String getToken() {
            return token;
        }

        public String getUserId() {
            return userId;
        }
    }

    public static class ErrorResponse {
        private final String message;
        private final String code;

        public ErrorResponse(String message, String code) {
            this.message = message;
            this.code = code;
        }

        public String getMessage() {
            return message;
        }

        public String getCode() {
            return code;
        }
    }

    public static class LogoutResponse {
        private final String message;

        public LogoutResponse(String message) {
            this.message = message;
        }

        public String getMessage() {
            return message;
        }
    }
}