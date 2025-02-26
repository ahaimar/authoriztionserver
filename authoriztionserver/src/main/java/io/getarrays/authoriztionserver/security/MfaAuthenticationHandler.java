package io.getarrays.authoriztionserver.security;

import io.getarrays.authoriztionserver.model.entity.User;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;

import java.io.IOException;

public class MfaAuthenticationHandler implements AuthenticationSuccessHandler{

    private final SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();
    private final AuthenticationSuccessHandler mfaNotEnable = new SavedRequestAwareAuthenticationSuccessHandler();
    private final AuthenticationSuccessHandler authenticationSuccessHandler;
    private final String authority;

    public MfaAuthenticationHandler(String successHrl, String authority) {
        SimpleUrlAuthenticationSuccessHandler authenticationSuccessHandler = new SimpleUrlAuthenticationSuccessHandler(successHrl);
        authenticationSuccessHandler.setAlwaysUseDefaultTargetUrl(true);
        this.authenticationSuccessHandler = authenticationSuccessHandler;
        this.authority = authority;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        if (authentication instanceof UsernamePasswordAuthenticationToken)  {
            var user = (User) authentication.getPrincipal();
            if (!user.isMfa()){
                mfaNotEnable.onAuthenticationSuccess(request, response, authentication);
                return;
            }
        }
        saveAuthentication(request, response, new MfaAuthentication(authentication, authority));
    }

    private void saveAuthentication(HttpServletRequest request, HttpServletResponse response, MfaAuthentication authentication) {

        SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
        securityContext.setAuthentication(authentication);
        SecurityContextHolder.setContext(securityContext);
        securityContextRepository.saveContext(securityContext, request, response);
    }
}
























