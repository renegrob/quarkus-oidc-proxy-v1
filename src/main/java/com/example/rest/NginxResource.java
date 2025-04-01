package com.example.rest;

import com.example.service.AuthService;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Base64;

/**
 * REST endpoints for NGINX integration
 */
@Path("/nginx")
@Produces(MediaType.APPLICATION_JSON)
public class NginxResource {
    private static final Logger LOG = LoggerFactory.getLogger(NginxResource.class);
    private static final String SESSION_COOKIE_NAME = "AUTH_SESSION";

    @Inject
    AuthService authService;

    @Context
    UriInfo uriInfo;

    /**
     * Endpoint for NGINX auth_request integration
     * This endpoint validates the session and provides authentication information to NGINX
     *
     * @param cookie The session cookie
     * @return HTTP 200 if authenticated, HTTP 401 otherwise
     */
    @GET
    @Path("/auth")
    public Response validateForNginx(@CookieParam(SESSION_COOKIE_NAME) Cookie cookie) {
        AuthService.ValidationResult result = authService.validateSession(cookie, uriInfo);

        if (!result.isValid()) {
            if (result.isExpired() && result.getInvalidationCookie() != null) {
                return Response.status(Response.Status.UNAUTHORIZED)
                        .cookie(result.getInvalidationCookie())
                        .build();
            }
            return Response.status(Response.Status.UNAUTHORIZED).build();
        }

        // Return the internal JWT in a header for NGINX to forward to backend services
        return Response.ok()
                .header("X-Auth-Token", result.getToken())
                .header("X-Auth-User-ID", result.getUserId())
                .build();
    }

    /**
     * Endpoint for NGINX to redirect unauthenticated users
     *
     * @param originalUri The original URI the user was trying to access
     * @param idpName The identity provider to use for authentication
     * @return Redirection to the IdP authentication page
     */
    @GET
    @Path("/login/{idpName}")
    public Response nginxLogin(
            @PathParam("idpName") String idpName,
            @QueryParam("redirect_uri") @DefaultValue("") String originalUri) {

        // Base64 encode the original URI to preserve special characters
        String encodedRedirect = originalUri.isEmpty() ? "" :
                Base64.getUrlEncoder().withoutPadding().encodeToString(originalUri.getBytes());

        // Construct login URL
        String loginUrl = uriInfo.getBaseUriBuilder()
                .path("auth")
                .path("login")
                .path(idpName)
                .queryParam("redirect_uri", encodedRedirect)
                .build()
                .toString();

        // Redirect to login
        return Response.status(Response.Status.FOUND)
                .header("Location", loginUrl)
                .build();
    }

    /**
     * Callback endpoint for redirecting after authentication
     *
     * @param encodedUri The base64 encoded original URI to redirect to
     * @return Redirection to the original URI
     */
    @GET
    @Path("/callback")
    public Response nginxCallback(@QueryParam("redirect_uri") String encodedUri) {
        try {
            String decodedUri = new String(Base64.getUrlDecoder().decode(encodedUri));

            return Response.status(Response.Status.FOUND)
                    .header("Location", decodedUri)
                    .build();
        } catch (Exception e) {
            LOG.error("Error decoding redirect URI", e);
            return Response.status(Response.Status.FOUND)
                    .header("Location", "/")
                    .build();
        }
    }
}