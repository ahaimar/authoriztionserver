package io.getarrays.authoriztionserver.security.utils;

import io.getarrays.authoriztionserver.model.entity.User;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;

public class UserUtils {

    public static User getUser(Authentication authontication){
        if (authontication instanceof OAuth2AuthorizationCodeRequestAuthenticationToken){

            var userNamePasswordAuthenticationToken = (UsernamePasswordAuthenticationToken) authontication.getPrincipal();
            return (User) userNamePasswordAuthenticationToken.getPrincipal();
        }

        return (User) authontication.getPrincipal();
    }
}
