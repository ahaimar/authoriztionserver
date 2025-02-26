package io.getarrays.authoriztionserver.security;

import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.util.Map;

public class ClientRefreshTokenAuthentication extends OAuth2ClientAuthenticationToken {

    public ClientRefreshTokenAuthentication(String clientId) {

        super(clientId, ClientAuthenticationMethod.NONE, null, null);
    }

    public ClientRefreshTokenAuthentication(RegisteredClient registeredClient) {

        super(registeredClient, ClientAuthenticationMethod.NONE, null);
    }
}
