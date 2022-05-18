package com.example.otpresourceserver.security.auth.managers;

import java.util.Collection;
import lombok.Getter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

@Getter
public class UsernamePasswordAuthentication extends UsernamePasswordAuthenticationToken {

    private String clientId;
    private String clientSecret;

    public UsernamePasswordAuthentication(Object principal, Object credentials, String clientId, String clientSecret) {
        this(principal, credentials);
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    public UsernamePasswordAuthentication(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
        super(principal, credentials, authorities);
    }

    public UsernamePasswordAuthentication(Object principal, Object credentials) {
        super(principal, credentials);
    }
}