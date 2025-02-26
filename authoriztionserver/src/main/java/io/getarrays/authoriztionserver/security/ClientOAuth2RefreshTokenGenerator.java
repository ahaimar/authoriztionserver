package io.getarrays.authoriztionserver.security;


import lombok.NoArgsConstructor;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Base64;

@Component
@NoArgsConstructor
public class ClientOAuth2RefreshTokenGenerator implements OAuth2TokenGenerator<OAuth2RefreshToken> {

    private final StringKeyGenerator refreshKeyGenerator = new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding());

    @Override
    public OAuth2RefreshToken generate(OAuth2TokenContext context) {
        if (!OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())){
            return null;
        }else {
            var issueAt = Instant.now();
            var expiresAt = issueAt.plus(context.getRegisteredClient().getTokenSettings().getAccessTokenTimeToLive());
            return new OAuth2RefreshToken(refreshKeyGenerator.generateKey(), issueAt, expiresAt);
        }
    }
}



























