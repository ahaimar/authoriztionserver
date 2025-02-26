package io.getarrays.authoriztionserver.security;

import lombok.Getter;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;

import static org.springframework.security.core.authority.AuthorityUtils.createAuthorityList;

@Getter
public class MfaAuthentication extends AnonymousAuthenticationToken {

    private final Authentication primaryAuthentication;

    public MfaAuthentication(Authentication authentication, String authority) {

        super("key", "principal", createAuthorityList("ROLE_ANONYMOUS", authority));
        this.primaryAuthentication = authentication;
    }

    @Override
    public Object getPrincipal() {
        return this.primaryAuthentication;
    }
}
