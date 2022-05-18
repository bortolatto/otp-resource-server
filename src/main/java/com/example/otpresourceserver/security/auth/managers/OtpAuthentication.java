package com.example.otpresourceserver.security.auth.managers;

import lombok.Getter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

@Getter
public class OtpAuthentication extends UsernamePasswordAuthenticationToken {
    private String clientId;
    private String clientSecret;

    public OtpAuthentication(Object principal, Object credentials, String clientId, String clientSecret) {
        this(principal, credentials);
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    public OtpAuthentication(Object principal, Object credentials) {
        super(principal, credentials);
    }
}