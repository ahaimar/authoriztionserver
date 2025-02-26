package io.getarrays.authoriztionserver.controller;

import io.getarrays.authoriztionserver.model.entity.User;
import io.getarrays.authoriztionserver.security.MfaAuthentication;
import io.getarrays.authoriztionserver.service.UserService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.IOException;

import static io.getarrays.authoriztionserver.security.utils.UserUtils.getUser;

@Controller
@AllArgsConstructor
public class LoginController {

    private final SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();
    private final AuthenticationSuccessHandler authenticationSuccessHandler = new SavedRequestAwareAuthenticationSuccessHandler();
    private final AuthenticationFailureHandler authenticationFailureHandler = new SimpleUrlAuthenticationFailureHandler("/mfa?error");
    private final UserService userService;

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @PostMapping("/mfa")
    public void validateCode(@RequestParam("code") String code, HttpServletRequest request, HttpServletResponse response, @CurrentSecurityContext SecurityContext context) throws ServletException, IOException {

        var user =  getUser(context.getAuthentication());
        if (userService.verifyQrCode(user.getUserUuid(), code)) {
            this.authenticationSuccessHandler.onAuthenticationSuccess(request, response, saveAuthentication(request, response));
            return;
        }
        this.authenticationFailureHandler.onAuthenticationFailure(request, response, new BadCredentialsException("Invalid Qr code. pls try again!!"));
    }

    private Authentication saveAuthentication(HttpServletRequest request, HttpServletResponse response) {


        SecurityContext securityContext = SecurityContextHolder.getContext();
        MfaAuthentication mfaAuthentication = (MfaAuthentication) securityContext.getAuthentication();
        securityContext.setAuthentication(mfaAuthentication);
        SecurityContextHolder.setContext(securityContext);
        securityContextRepository.saveContext(securityContext, request, response);
        return  mfaAuthentication.getPrimaryAuthentication();
    }

    private Object getAuthenticationUser(Authentication authentication) {

        return ((User) authentication.getPrincipal()).getEmail();
    }

}




















