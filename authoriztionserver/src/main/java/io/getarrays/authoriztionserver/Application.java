package io.getarrays.authoriztionserver;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;

import static java.util.UUID.randomUUID;

@Slf4j
@SpringBootApplication
@EnableDiscoveryClient
public class Application {


	@Value("${io.app.url}")
	private String redirectUri;

	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	}

	@Bean
	public ApplicationRunner runner(RegisteredClientRepository registeredClientRepository) {
		return args -> {

			if (registeredClientRepository.findByClientId("client") == null) {
				try{
					var registeredClient = RegisteredClient.withId(randomUUID().toString())
							.clientId("client")
							.clientSecret("secret")
							.clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
							.authorizationGrantTypes(types -> {
								types.add(AuthorizationGrantType.AUTHORIZATION_CODE);
								types.add(AuthorizationGrantType.REFRESH_TOKEN);
							})
							.scopes(scopes -> {
								scopes.add(OidcScopes.OPENID);
								scopes.add(OidcScopes.PROFILE);
								scopes.add(OidcScopes.EMAIL);
							})
							.redirectUri(redirectUri)
							.postLogoutRedirectUri("http://172.0.0.1.8080")
							.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
							.tokenSettings(TokenSettings.builder().refreshTokenTimeToLive(Duration.ofDays(90))
									.accessTokenTimeToLive(Duration.ofDays(1)).build()).build();
					registeredClientRepository.save(registeredClient);
				}catch(Exception e){
					log.error("Error initializing client: {}", e.getMessage());

				}
			}
		};
	}
}
