package com.example.otpresourceserver.filter;

import com.example.otpresourceserver.security.auth.managers.OtpAuthentication;
import com.example.otpresourceserver.security.auth.managers.UsernamePasswordAuthentication;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Objects;
import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.web.filter.OncePerRequestFilter;

@RequiredArgsConstructor
public class InitialAuthenticationFilter extends OncePerRequestFilter {

    private final AuthenticationManager manager;
    private final String signingKey;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authorization = request.getHeader("Authorization");
        String clientId = "";
        String clientSecret = "";
        if (Objects.nonNull(authorization)) {
            String[] split = authorization.split(":");
            clientId = split[0].split(" ")[1];
            clientSecret = split[1];
        }

        String username = request.getHeader("username");
        String password = request.getHeader("password");
        String code = request.getHeader("code");

        if (Objects.isNull(code) || code.isBlank()) {
            Authentication authentication = new UsernamePasswordAuthentication(username, password, clientId, clientSecret);
            manager.authenticate(authentication);
        } else {
            Authentication otpAuth = new OtpAuthentication(username, code, clientId, clientSecret);
            manager.authenticate(otpAuth);

            SecretKey key = Keys.hmacShaKeyFor(signingKey.getBytes(StandardCharsets.UTF_8));
            String jwt = Jwts.builder()
                .setClaims(Map.of("username", username))
                .signWith(key)
                .compact();

            response.setHeader("Authorization", jwt);
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getServletPath().equals("/login");
    }
}