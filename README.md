# Quarkus OAuth2/OpenID Connect Delegate for NGINX

This application serves as an authentication delegate for NGINX, handling OAuth2 and OpenID Connect (OIDC) authentication with various identity providers. It manages user sessions using Infinispan embedded cache and provides internal JWT tokens for backend services.

## Features

- OAuth2 and OpenID Connect authentication with multiple identity providers:
    - Microsoft Entra ID (formerly Azure AD)
    - Google
    - Facebook
    - Amazon Cognito
    - Any other OAuth2/OIDC compliant provider
- Session management with cookies
- Session storage in Infinispan embedded cache
- Token management (storing OAuth tokens in the session)
- Internal JWT token generation for backend services
- Support for token refreshing
- NGINX integration

## Technology Stack

- Quarkus 3.21.0
- Java 21+
- Gradle with Kotlin DSL build script
- Infinispan embedded for session storage
- SmallRye JWT for token generation and verification

## Configuration

The application uses `application.yaml` for configuration. Here are the key configuration points:

### Identity Provider Configuration

Configure one or more identity providers in the `quarkus.oidc.tenant-config` section:

```yaml
quarkus:
  oidc:
    tenant-config:
      # Microsoft EntraID
      entra:
        auth-server-url: https://login.microsoftonline.com/${ENTRA_TENANT_ID}/v2.0
        client-id: ${ENTRA_CLIENT_ID}
        credentials:
          secret: ${ENTRA_CLIENT_SECRET}
      # Google
      google:
        auth-server-url: https://accounts.google.com
        client-id: ${GOOGLE_CLIENT_ID}
        credentials:
          secret: ${GOOGLE_CLIENT_SECRET}
      # Add other providers as needed
```

### Session Configuration

Configure session settings in the Infinispan configuration:

```yaml
quarkus:
  infinispan:
    embedded:
      cluster-name: auth-delegate-cluster
      config-file: infinispan.xml
```

The `infinispan.xml` file contains detailed cache configuration for sessions and JWT keys.

### JWT Token Configuration

Configure JWT token generation:

```yaml
quarkus:
  jwt:
    signing-key-location: ${JWT_SIGNING_KEY_LOCATION:}
    internal-token-expiration: ${JWT_INTERNAL_TOKEN_EXPIRATION:3600}
    internal-token-issuer: ${JWT_INTERNAL_TOKEN_ISSUER:oauth-delegate}
    internal-token-audience: ${JWT_INTERNAL_TOKEN_AUDIENCE:backend-services}
```

## Building the Application

```bash
./gradlew build
```

## Running the Application

```bash
java -jar build/quarkus-app/quarkus-run.jar
```

Or in development mode:

```bash
./gradlew quarkusDev
```

## Environment Variables

Use the quarkus.infinispan-embedded.xml-config property to set the path to an XML file that includes the configuration of the injected instance.

Configure the following environment variables:

- `SESSION_ENCRYPTION_KEY`: Key for encrypting session data (32 chars)
- `OAUTH_SERVER_URL`, `OAUTH_CLIENT_ID`, `OAUTH_CLIENT_SECRET`: Default OAuth configuration
- For Entra ID: `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`, `ENTRA_CLIENT_SECRET`
- For Google: `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`
- For Facebook: `FACEBOOK_CLIENT_ID`, `FACEBOOK_CLIENT_SECRET`
- For Cognito: `COGNITO_DOMAIN`, `COGNITO_REGION`, `COGNITO_CLIENT_ID`, `COGNITO_CLIENT_SECRET`, `COGNITO_USER_POOL_ID`
- JWT configuration: `JWT_SIGNING_KEY_LOCATION`, `JWT_INTERNAL_TOKEN_EXPIRATION`, `JWT_INTERNAL_TOKEN_ISSUER`, `JWT_INTERNAL_TOKEN_AUDIENCE`

## Integration with NGINX

### NGINX Configuration

```nginx
# Authentication check
auth_
```
