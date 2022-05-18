package com.example.otpresourceserver.security.auth.providers;

import com.example.otpresourceserver.security.auth.managers.OtpAuthentication;
import com.example.otpresourceserver.security.auth.proxy.AuthenticationServerProxy;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

@RequiredArgsConstructor
@Component
public class OtpAuthenticationProvider implements AuthenticationProvider {

    private final AuthenticationServerProxy authenticationServerProxy;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String code = authentication.getCredentials().toString();

        OtpAuthentication otpAuthentication = (OtpAuthentication) authentication;
        String clientId = otpAuthentication.getClientId();
        String clientSecret = otpAuthentication.getClientSecret();

        boolean authenticated = authenticationServerProxy.sendOTP(username, code, clientId, clientSecret);
        if (authenticated) {
            // ainda não está autenticado
            return new OtpAuthentication(username, code);
        } else {
            throw new BadCredentialsException("Bad credentials.");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OtpAuthentication.class.isAssignableFrom(authentication);
    }
}
