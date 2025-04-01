package com.example.config;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.context.RequestScoped;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.UriInfo;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Configuration provider for multi-tenant OIDC support
 */
@ApplicationScoped
public class MultitenantConfig {
    private static final Logger LOG = Logger.getLogger(MultitenantConfig.class);

    private static final Pattern TENANT_PATH_PATTERN = Pattern.compile("^auth/login/([a-zA-Z0-9_-]+)");

    @Inject
    @Context
    HttpHeaders headers;

    @Inject
    @Context
    UriInfo uriInfo;

    @ConfigProperty(name = "quarkus.oidc.tenant-config.default", defaultValue = "default")
    String defaultTenant;

    /**
     * Produces the current tenant identifier based on path parameters or headers
     *
     * @return The tenant identifier
     */
    @Produces
    @RequestScoped
    public String tenantId() {
        // Try to extract tenant from path parameter
        String pathTenant = extractTenantFromPath();
        if (pathTenant != null && !pathTenant.isEmpty()) {
            LOG.debugf("Using tenant from path: %s", pathTenant);
            return pathTenant;
        }

        // Try to extract tenant from custom header
        String headerTenant = headers.getHeaderString("X-Tenant-ID");
        if (headerTenant != null && !headerTenant.isEmpty()) {
            LOG.debugf("Using tenant from header: %s", headerTenant);
            return headerTenant;
        }

        // Fall back to default tenant
        LOG.debugf("Using default tenant: %s", defaultTenant);
        return defaultTenant;
    }

    private String extractTenantFromPath() {
        String path = uriInfo.getPath();

        // Check if path contains /auth/login/{tenant} or /auth/callback/{tenant}
        Matcher matcher = TENANT_PATH_PATTERN.matcher(path);
        if (matcher.matches()) {
            return matcher.group(1);
        }

        return null;
    }
}