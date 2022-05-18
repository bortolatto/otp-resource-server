package com.example.otpresourceserver.security.auth.providers;

import com.example.otpresourceserver.security.auth.managers.UsernamePasswordAuthentication;
import com.example.otpresourceserver.security.auth.proxy.AuthenticationServerProxy;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

@RequiredArgsConstructor
@Component
public class UsernamePasswordAuthenticationProvider implements AuthenticationProvider {

    private final AuthenticationServerProxy authenticationServerProxy;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();

        UsernamePasswordAuthentication usernamePasswordAuthentication = (UsernamePasswordAuthentication) authentication;
        String clientId = usernamePasswordAuthentication.getClientId();
        String clientSecret = usernamePasswordAuthentication.getClientSecret();

        authenticationServerProxy.sendAuth(username, password, clientId, clientSecret);

        // ainda não está autenticado
        return new UsernamePasswordAuthentication(username, password);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthentication.class.isAssignableFrom(authentication);
    }
}
