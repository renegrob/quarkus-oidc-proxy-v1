package com.example.rest;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * Health check endpoint
 */
@Path("/health")
@ApplicationScoped
public class HealthResource {

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response healthCheck() {
        Map<String, Object> health = new HashMap<>();
        health.put("status", "UP");
        health.put("timestamp", Instant.now().toString());

        return Response.ok(health).build();
    }
}