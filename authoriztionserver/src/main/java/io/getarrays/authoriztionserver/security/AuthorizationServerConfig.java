package io.getarrays.authoriztionserver.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.CookieClearingLogoutHandler;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;
import java.util.stream.Collectors;

import static org.springframework.http.HttpHeaders.*;
import static org.springframework.http.HttpMethod.*;
import static org.springframework.security.oauth2.server.authorization.OAuth2TokenType.ACCESS_TOKEN;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class AuthorizationServerConfig {
    private final JwtConfiguration jwtConfiguration;

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationSecurityConfig(HttpSecurity http, RegisteredClientRepository registeredClientRepository)
            throws Exception {

        http.cors(corsConfigurer -> corsConfigurer.configurationSource(corsConfigurationSource()));

        var authorizationConfig = OAuth2AuthorizationServerConfigurer.authorizationServer()
                .tokenGenerator(tokenGenerator())
                .clientAuthentication(authenticotion -> {
                    authenticotion.authenticationConverter(new ClientRefreshTokenAuthenticationConverter());
                    authenticotion.authenticationProvider(new ClientAuthenticationProvider(registeredClientRepository));
                })
                .oidc(Customizer.withDefaults());
        http.securityMatcher(authorizationConfig.getEndpointsMatcher()).
                with(authorizationConfig , Customizer.withDefaults()).
                exceptionHandling(exception -> exception.accessDeniedPage("/accessDenied").
                        defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML))
                );

        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http.cors(corsConfigurer -> corsConfigurer.configurationSource(corsConfigurationSource()));

        http.authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/login").permitAll()
                        .requestMatchers(POST,"/logout").permitAll()
                        .requestMatchers("/mfa").hasAnyAuthority("MFA_REQUIRED")
                        .anyRequest().authenticated()
        );
        http.formLogin(login -> login
                .loginPage("/login")
                .successHandler(new MfaAuthenticationHandler("/mfa", "MFA_REQUIRED"))
                .failureHandler(new SimpleUrlAuthenticationFailureHandler("/login?error"))
        );
        http.logout(logout -> logout.logoutSuccessUrl("http://localhost:3000")
               .addLogoutHandler(new CookieClearingLogoutHandler("JSESSIONID"))
        );
        return http.build();
    }

    @Bean
    public OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator() {

        var jwtGenerator = UserJwtGenerator.init(new NimbusJwtEncoder((jwtConfiguration.jwkSource())));
        jwtGenerator.setJwtCustomizer(customizer());
        OAuth2TokenGenerator<OAuth2RefreshToken> refreshTokenOAuth2TokenGenerator = new ClientOAuth2RefreshTokenGenerator();

        return  new DelegatingOAuth2TokenGenerator(jwtGenerator, refreshTokenOAuth2TokenGenerator);
    }

    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler() {

        return new SavedRequestAwareAuthenticationSuccessHandler();
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {

        return AuthorizationServerSettings.builder().build();
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> customizer(){
        return context -> {
            if (ACCESS_TOKEN.equals(context.getTokenType())){
                context.getClaims().claims(claims-> claims.put("authorities", getAuthorities(context)));
            }
        };
    }

    private String getAuthorities(JwtEncodingContext context) {

        return context.getPrincipal().getAuthorities() == null ? "" :
                context.getPrincipal().getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.joining(", "));
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        return new JdbcRegisteredClientRepository(jdbcTemplate);
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        var corsConfiguration = new CorsConfiguration();
        corsConfiguration.setAllowCredentials(true);

        // ✅ Fixed Allowed Origins (Corrected Port Separators)
        corsConfiguration.setAllowedOrigins(List.of(
                "http://192.168.1.157:3000",
                "http://localhost:3000",
                "http://192.168.1.159:3000",
                "http://localhost:4200",
                "100.14.214.212:3000",
                "http://localhost:4200",
                "http://localhost:3000",
                "http://192.168.1.216:3000",
                "*"
        ));

        // ✅ Fixed Allowed Headers
        corsConfiguration.setAllowedHeaders(List.of(
                ORIGIN,
                ACCESS_CONTROL_ALLOW_ORIGIN,
                CONTENT_TYPE,
                ACCEPT,
                AUTHORIZATION,
                "X-Requested-With",
                ACCESS_CONTROL_REQUEST_METHOD,
                ACCESS_CONTROL_REQUEST_HEADERS,
                ACCESS_CONTROL_ALLOW_CREDENTIALS
        ));

        // ✅ Fixed Allowed Methods
        corsConfiguration.setAllowedMethods(List.of(
                GET.name(),
                POST.name(),
                PUT.name(),
                PATCH.name(),
                DELETE.name(),
                OPTIONS.name()
        ));

        corsConfiguration.setMaxAge(3600L); // ✅ Fixed long value format

        var source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfiguration);

        return source;
    }
}