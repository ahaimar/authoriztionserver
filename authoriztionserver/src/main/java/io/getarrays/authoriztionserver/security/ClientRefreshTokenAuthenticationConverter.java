package io.getarrays.authoriztionserver.security;


import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.stereotype.Component;

@Component
public class ClientRefreshTokenAuthenticationConverter implements AuthenticationConverter {


    @Override
    public Authentication convert(HttpServletRequest request) {

        var granType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
        if (granType.equals(AuthorizationGrantType.REFRESH_TOKEN.getValue())) {
            return null;
        }
        var clientId =  request.getParameter(OAuth2ParameterNames.CLIENT_ID);
        return new ClientRefreshTokenAuthentication(clientId);
    }
}
