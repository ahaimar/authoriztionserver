package io.getarrays.authoriztionserver.security;


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

@Configuration
@RequiredArgsConstructor
public class JwtConfiguration {

    private final KeyUtils keyUtils;

    @Bean
    public JwtDecoder jwtDecoder() throws JOSEException {
        return NimbusJwtDecoder.withPublicKey(keyUtils.getRSAKeyPair().toRSAPublicKey()).build();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource(){

        RSAKey rsaKey = keyUtils.getRSAKeyPair();
        JWKSet set = new JWKSet(rsaKey);
        return (j, sc) -> j.select(set);
    }

}